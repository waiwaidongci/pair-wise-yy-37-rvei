from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        deact_statuses = ",".join("'" + s.replace("'", "''") + "'" for s in ('frozen', 'released', 'invalidated'))
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    facility TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ref TEXT NOT NULL UNIQUE,
                    facility TEXT NOT NULL,
                    name TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deactivation_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT NOT NULL UNIQUE,
                    device_ref TEXT NOT NULL,
                    facility TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'frozen'
                        CHECK(status IN ({deact_statuses})),
                    release_conclusion TEXT,
                    released_by TEXT,
                    released_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_deactivation_device_period
                    ON deactivation_batches(device_ref, period_start, period_end);
                CREATE TABLE IF NOT EXISTS batch_permits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL
                        REFERENCES deactivation_batches(id) ON DELETE CASCADE,
                    item_id INTEGER NOT NULL
                        REFERENCES items(id) ON DELETE CASCADE,
                    frozen INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(batch_id, item_id)
                );
                CREATE TABLE IF NOT EXISTS batch_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL
                        REFERENCES deactivation_batches(id) ON DELETE CASCADE,
                    record_id INTEGER NOT NULL
                        REFERENCES records(id) ON DELETE CASCADE,
                    frozen INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(batch_id, record_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)
            # 迁移：为旧库补充 facility 列
            cols = self.conn.execute("PRAGMA table_info(items)").fetchall()
            if not any(c["name"] == "facility" for c in cols):
                self.conn.execute("ALTER TABLE items ADD COLUMN facility TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, facility: str = "") -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, facility, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, facility, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        if self.is_item_frozen(item_id):
            raise ConflictError("许可已被停用交接冻结，不能转换状态")
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def update_record_status(self, record_id: int, status: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE records SET status=? WHERE id=?",
                (status, record_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM records WHERE id=?", (record_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("记录不存在")
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---- 设施与设备 ----
    def create_device(self, device_ref: str, facility: str, name: Optional[str],
                      actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO devices(device_ref, facility, name, created_by, created_at)
                       VALUES(?,?,?,?,?)""",
                    (device_ref, facility, name, actor, now),
                )
                device_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("设备标识已存在") from exc
        return self.get_device_by_id(device_id)

    def get_device_by_id(self, device_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if row is None:
            raise NotFoundError("设备不存在")
        return dict(row)

    def get_device(self, device_ref: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM devices WHERE device_ref=?", (device_ref,)
            ).fetchone()
        if row is None:
            raise NotFoundError("设备不存在")
        return dict(row)

    def list_items_by_facility(self, facility: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE facility=? ORDER BY id", (facility,)
            ).fetchall()
        return [self._item(row) for row in rows]

    def list_open_records_for_items(self, item_ids: List[int]) -> List[Dict[str, Any]]:
        if not item_ids:
            return []
        placeholders = ",".join("?" for _ in item_ids)
        with self._lock:
            rows = self.conn.execute(
                f"""SELECT * FROM records
                    WHERE item_id IN ({placeholders}) AND status='open'
                    ORDER BY id""",
                item_ids,
            ).fetchall()
        return [dict(row) for row in rows]

    # ---- 停用批次 ----
    def create_deactivation_batch(self, batch_no: str, device_ref: str, facility: str,
                                   period_start: str, period_end: str,
                                   actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO deactivation_batches
                       (batch_no, device_ref, facility, period_start, period_end,
                        status, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?, 'frozen', ?,?,?)""",
                    (batch_no, device_ref, facility, period_start, period_end,
                     actor, now, now),
                )
                batch_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("停用批次已存在") from exc
        return self.get_deactivation_batch(batch_id)

    def get_deactivation_batch(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM deactivation_batches WHERE id=?", (batch_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("停用批次不存在")
        return dict(row)

    def get_deactivation_batch_by_key(self, device_ref: str, period_start: str,
                                      period_end: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM deactivation_batches
                   WHERE device_ref=? AND period_start=? AND period_end=?""",
                (device_ref, period_start, period_end),
            ).fetchone()
        if row is None:
            raise NotFoundError("停用批次不存在")
        return dict(row)

    def list_deactivation_batches(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM deactivation_batches ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def freeze_batch_permits(self, batch_id: int, item_ids: List[int]) -> None:
        if not item_ids:
            return
        with self._lock, self.conn:
            self.conn.executemany(
                """INSERT OR IGNORE INTO batch_permits(batch_id, item_id, frozen)
                   VALUES(?,?,1)""",
                [(batch_id, item_id) for item_id in item_ids],
            )

    def freeze_batch_records(self, batch_id: int, record_ids: List[int]) -> None:
        if not record_ids:
            return
        with self._lock, self.conn:
            self.conn.executemany(
                """INSERT OR IGNORE INTO batch_records(batch_id, record_id, frozen)
                   VALUES(?,?,1)""",
                [(batch_id, record_id) for record_id in record_ids],
            )

    def reset_batch_permits(self, batch_id: int, item_ids: List[int]) -> None:
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM batch_permits WHERE batch_id=?", (batch_id,))
            self.freeze_batch_permits(batch_id, item_ids)

    def reset_batch_records(self, batch_id: int, record_ids: List[int]) -> None:
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM batch_records WHERE batch_id=?", (batch_id,))
            self.freeze_batch_records(batch_id, record_ids)

    def list_batch_permits(self, batch_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT i.* FROM batch_permits bp
                   JOIN items i ON i.id=bp.item_id
                   WHERE bp.batch_id=? ORDER BY i.id""",
                (batch_id,),
            ).fetchall()
        return [self._item(row) for row in rows]

    def list_batch_records(self, batch_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT r.* FROM batch_records br
                   JOIN records r ON r.id=br.record_id
                   WHERE br.batch_id=? ORDER BY r.id""",
                (batch_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def release_batch(self, batch_id: int, conclusion: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE deactivation_batches
                   SET status='released', release_conclusion=?, released_by=?,
                       released_at=?, updated_at=?
                   WHERE id=? AND status='frozen'""",
                (conclusion, actor, now, now, batch_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM deactivation_batches WHERE id=?", (batch_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("停用批次不存在")
                raise ConflictError("批次已放行或已失效，不能重复放行")
        return self.get_deactivation_batch(batch_id)

    def invalidate_batch(self, batch_id: int) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE deactivation_batches
                   SET status='invalidated', release_conclusion=NULL,
                       released_by=NULL, released_at=NULL, updated_at=?
                   WHERE id=? AND status='released'""",
                (now, batch_id),
            )
            if cur.rowcount == 0:
                return self.get_deactivation_batch(batch_id)
        return self.get_deactivation_batch(batch_id)

    def find_batches_for_item(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT DISTINCT b.* FROM deactivation_batches b
                   JOIN batch_permits bp ON bp.batch_id=b.id
                   WHERE bp.item_id=? ORDER BY b.id""",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_released_batches_for_item(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT DISTINCT b.* FROM deactivation_batches b
                   JOIN batch_permits bp ON bp.batch_id=b.id
                   WHERE bp.item_id=? AND b.status='released'""",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def is_item_frozen(self, item_id: int) -> bool:
        with self._lock:
            row = self.conn.execute(
                """SELECT 1 FROM batch_permits bp
                   JOIN deactivation_batches b ON b.id=bp.batch_id
                   WHERE bp.item_id=? AND b.status='frozen' LIMIT 1""",
                (item_id,),
            ).fetchone()
        return row is not None
