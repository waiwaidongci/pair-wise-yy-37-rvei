from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (BATCH_ACTIVE, BATCH_ID_PREFIX, BATCH_PENDING,
                    EFFECT_INSPECTION_FROZEN, EFFECT_PERMIT_FROZEN,
                    RELEASE_INVALIDATED, RELEASE_VALID, STATES)


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
                    equipment_id INTEGER REFERENCES equipment(id),
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
                CREATE TABLE IF NOT EXISTS equipment (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    facility TEXT NOT NULL,
                    name TEXT NOT NULL,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(facility, name)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_equipment_external_ref
                    ON equipment(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS deactivation_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT UNIQUE,
                    equipment_id INTEGER NOT NULL REFERENCES equipment(id),
                    facility TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT '{BATCH_PENDING}'
                        CHECK(status IN ('{BATCH_PENDING}','{BATCH_ACTIVE}')),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deactivation_effects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES deactivation_batches(id)
                        ON DELETE CASCADE,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    record_id INTEGER NOT NULL DEFAULT 0,
                    effect TEXT NOT NULL CHECK(effect IN
                        ('permit_frozen','inspection_frozen','rectification_open')),
                    created_at TEXT NOT NULL,
                    UNIQUE(batch_id, item_id, effect, record_id)
                );
                CREATE TABLE IF NOT EXISTS releases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT '{RELEASE_VALID}'
                        CHECK(status IN ('{RELEASE_VALID}','{RELEASE_INVALIDATED}')),
                    decision TEXT NOT NULL CHECK(decision IN ('released','held')),
                    basis_signature TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    invalidated_at TEXT
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
            columns = [row[1] for row in self.conn.execute("PRAGMA table_info(items)")]
            if "equipment_id" not in columns:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN equipment_id INTEGER "
                    "REFERENCES equipment(id)")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, equipment_id: Optional[int] = None) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, equipment_id, created_by,
                       created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, equipment_id, actor, now, now),
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

    def get_record(self, record_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise NotFoundError("记录不存在")
        return dict(row)

    def close_record(self, item_id: int, record_id: int) -> Dict[str, Any]:
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE records SET status='closed' WHERE id=? AND item_id=? "
                "AND status='open'",
                (record_id, item_id),
            )
            if cur.rowcount == 0:
                row = self.conn.execute(
                    "SELECT * FROM records WHERE id=? AND item_id=?",
                    (record_id, item_id),
                ).fetchone()
                if row is None:
                    raise NotFoundError("记录不存在")
                raise ConflictError("记录已关闭")
        return self.get_record(record_id)

    def create_equipment(self, facility: str, name: str,
                         external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO equipment(facility, name, external_ref, created_by,
                       created_at) VALUES(?,?,?,?,?)""",
                    (facility, name, external_ref, actor, now),
                )
                equipment_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("设备已存在") from exc
        return self.get_equipment(equipment_id)

    def get_equipment(self, equipment_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM equipment WHERE id=?", (equipment_id,)).fetchone()
        if row is None:
            raise NotFoundError("设备不存在")
        return dict(row)

    def find_equipment_by_ref(self, external_ref: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM equipment WHERE external_ref=?",
                (external_ref,),
            ).fetchone()
        if row is None:
            raise NotFoundError("设备不存在")
        return dict(row)

    def list_equipment(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM equipment ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def items_for_equipment(self, equipment_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE equipment_id=? ORDER BY id",
                (equipment_id,),
            ).fetchall()
        return [self._item(row) for row in rows]

    def ensure_deactivation_batch(self, equipment_id: int, facility: str,
                                  period_start: str, period_end: str,
                                  key: str, actor: str) -> tuple:
        with self._lock:
            existing = self.find_batch_by_key(key)
            if existing is not None:
                return existing, True
            now = utc_now()
            try:
                with self.conn:
                    cur = self.conn.execute(
                        """INSERT INTO deactivation_batches(batch_no, equipment_id,
                           facility, period_start, period_end, status,
                           idempotency_key, created_by, created_at)
                           VALUES(NULL,?,?,?,?,?,?,?,?)""",
                        (equipment_id, facility, period_start, period_end,
                         BATCH_PENDING, key, actor, now),
                    )
                    batch_id = int(cur.lastrowid)
                    batch_no = f"{BATCH_ID_PREFIX}-{batch_id:06d}"
                    self.conn.execute(
                        "UPDATE deactivation_batches SET batch_no=? WHERE id=?",
                        (batch_no, batch_id),
                    )
            except sqlite3.IntegrityError:
                existing = self.find_batch_by_key(key)
                if existing is None:
                    raise
                return existing, True
        return self.get_batch(batch_id), False

    def get_batch(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM deactivation_batches WHERE id=?",
                (batch_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("停用批次不存在")
        return dict(row)

    def find_batch_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM deactivation_batches WHERE idempotency_key=?",
                (key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def list_batches(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM deactivation_batches ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

    def apply_deactivation_effects(self, batch_id: int,
                                   effects: List[Dict[str, Any]]) -> tuple:
        now = utc_now()
        try:
            with self._lock:
                with self.conn:
                    row = self.conn.execute(
                        "SELECT status FROM deactivation_batches WHERE id=?",
                        (batch_id,),
                    ).fetchone()
                    if row is None:
                        raise NotFoundError("停用批次不存在")
                    if row["status"] == BATCH_ACTIVE:
                        applied = False
                    else:
                        for effect in effects:
                            self.conn.execute(
                                """INSERT INTO deactivation_effects(batch_id,
                                   item_id, record_id, effect, created_at)
                                   VALUES(?,?,?,?,?)""",
                                (batch_id, effect["item_id"],
                                 effect.get("record_id", 0), effect["effect"],
                                 now),
                            )
                        self.conn.execute(
                            "UPDATE deactivation_batches SET status=? WHERE id=?",
                            (BATCH_ACTIVE, batch_id),
                        )
                        applied = True
        except sqlite3.IntegrityError:
            batch = self.get_batch(batch_id)
            if batch["status"] == BATCH_ACTIVE:
                return batch, False
            raise
        return self.get_batch(batch_id), applied

    def batch_effects(self, batch_id: int) -> List[Dict[str, Any]]:
        self.get_batch(batch_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM deactivation_effects WHERE batch_id=? ORDER BY id",
                (batch_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def item_frozen(self, item_id: int) -> bool:
        with self._lock:
            row = self.conn.execute(
                """SELECT 1 FROM deactivation_effects e
                   JOIN deactivation_batches b ON b.id=e.batch_id
                   WHERE e.item_id=? AND e.effect=? AND b.status=? LIMIT 1""",
                (item_id, EFFECT_PERMIT_FROZEN, BATCH_ACTIVE),
            ).fetchone()
        return row is not None

    def record_frozen(self, record_id: int) -> bool:
        with self._lock:
            row = self.conn.execute(
                """SELECT 1 FROM deactivation_effects e
                   JOIN deactivation_batches b ON b.id=e.batch_id
                   WHERE e.record_id=? AND e.effect=? AND b.status=? LIMIT 1""",
                (record_id, EFFECT_INSPECTION_FROZEN, BATCH_ACTIVE),
            ).fetchone()
        return row is not None

    def release_basis(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT id, kind, status FROM records
                   WHERE item_id=? AND kind IN ('inspection','rectification')
                   ORDER BY id""",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recompute_release(self, item_id: int, decision: str, signature: str,
                          actor: str) -> tuple:
        now = utc_now()
        with self._lock, self.conn:
            current = self.conn.execute(
                "SELECT * FROM releases WHERE item_id=? AND status=? "
                "ORDER BY id DESC LIMIT 1",
                (item_id, RELEASE_VALID),
            ).fetchone()
            if current is not None and current["basis_signature"] == signature:
                return dict(current), False
            self.conn.execute(
                "UPDATE releases SET status=?, invalidated_at=? "
                "WHERE item_id=? AND status=?",
                (RELEASE_INVALIDATED, now, item_id, RELEASE_VALID),
            )
            cur = self.conn.execute(
                """INSERT INTO releases(item_id, status, decision, basis_signature,
                   created_by, created_at) VALUES(?,?,?,?,?,?)""",
                (item_id, RELEASE_VALID, decision, signature, actor, now),
            )
            release_id = int(cur.lastrowid)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM releases WHERE id=?", (release_id,)).fetchone()
        return dict(row), True

    def list_releases(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM releases WHERE item_id=? ORDER BY id",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]

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
