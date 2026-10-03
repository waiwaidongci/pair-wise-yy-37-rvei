from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, DEACTIVATION_ROLES, ENTITY,
                    RECORD_ROLES, RELEASE_ROLES, TITLE, VIEW_ROLES,
                    can_release_deactivation, completion_blockers,
                    escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_deactivation_period, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        facility = payload.get("facility", "")
        if facility:
            facility = require_text(facility, "facility", 200)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, facility)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "facility": facility,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        # 记录改动后，关联放行失效重算
        self._invalidate_releases_for_item(item_id, actor)
        return record

    def update_record_status(self, record_id: int, status: str, actor: str,
                             role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        record = self.repository.update_record_status(record_id, status, actor)
        self.repository.append_audit("record", ENTITY, record["item_id"], actor, {
            "record_id": record["id"], "kind": record["kind"], "status": status,
        })
        self._invalidate_releases_for_item(record["item_id"], actor)
        return record

    def _invalidate_releases_for_item(self, item_id: int, actor: str) -> None:
        # 记录改动后：所有含该许可的批次重算快照；已放行的批次失效
        for batch in self.repository.find_batches_for_item(item_id):
            self._recalculate_batch(batch["id"])
            if batch["status"] == "released":
                self.repository.invalidate_batch(batch["id"])
                self.repository.append_audit("invalidate", "deactivation", batch["id"], actor, {
                    "reason": "record_changed", "item_id": item_id,
                })

    def _recalculate_batch(self, batch_id: int) -> Dict[str, Any]:
        batch = self.repository.get_deactivation_batch(batch_id)
        items = self.repository.list_items_by_facility(batch["facility"])
        item_ids = [item["id"] for item in items]
        records = self.repository.list_open_records_for_items(item_ids)
        record_ids = [rec["id"] for rec in records]
        self.repository.reset_batch_permits(batch_id, item_ids)
        self.repository.reset_batch_records(batch_id, record_ids)
        return self.repository.get_deactivation_batch(batch_id)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ---- 设备登记 ----
    def register_device(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, DEACTIVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        device_ref = require_text(payload.get("device_ref"), "device_ref", 100)
        facility = require_text(payload.get("facility"), "facility", 200)
        name = payload.get("name")
        if name is not None:
            name = require_text(name, "name", 200)
        device = self.repository.create_device(device_ref, facility, name, actor)
        self.repository.append_audit("register_device", "device", device["id"], actor, {
            "device_ref": device_ref, "facility": facility,
        })
        return device

    # ---- 停用影响交接 ----
    def submit_deactivation(self, payload: Dict[str, Any], actor: str, role: str):
        ensure_role(role, DEACTIVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        device_ref = require_text(payload.get("device_ref"), "device_ref", 100)
        period_start, period_end = validate_deactivation_period(
            payload.get("period_start"), payload.get("period_end"))
        device = self.repository.get_device(device_ref)
        facility = device["facility"]
        batch_no = payload.get("batch_no")
        if batch_no:
            batch_no = require_text(batch_no, "batch_no", 100)
        else:
            batch_no = f"DE-{uuid.uuid4().hex[:12]}"
        # 先到者生效：重复提交沿用首次批次
        try:
            batch = self.repository.create_deactivation_batch(
                batch_no, device_ref, facility, period_start, period_end, actor)
            created = True
        except ConflictError:
            batch = self.repository.get_deactivation_batch_by_key(
                device_ref, period_start, period_end)
            created = False
        # 冻结受影响许可和待执行检查（幂等，可重试）
        self._recalculate_batch(batch["id"])
        if created:
            self.repository.append_audit("deactivate", "deactivation", batch["id"], actor, {
                "device_ref": device_ref, "facility": facility,
                "period_start": period_start, "period_end": period_end,
                "batch_no": batch_no,
            })
        return self.get_deactivation(batch["id"], role), created

    def retry_deactivation(self, batch_id: int, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, DEACTIVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        batch = self.repository.get_deactivation_batch(batch_id)
        # 写入失败后保留原批次并按原编号重试
        self._recalculate_batch(batch["id"])
        self.repository.append_audit("retry", "deactivation", batch["id"], actor, {
            "batch_no": batch["batch_no"],
        })
        return self.get_deactivation(batch["id"], role)

    def release_deactivation(self, batch_id: int, payload: Dict[str, Any],
                             actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, RELEASE_ROLES)
        actor = require_text(actor, "actor", 100)
        conclusion = require_text(payload.get("conclusion"), "conclusion", 2000)
        batch = self.repository.get_deactivation_batch(batch_id)
        if not can_release_deactivation(batch["status"]):
            raise ConflictError("批次当前状态不能放行")
        # 放行前重算一次，确保包含晚到的检查
        self._recalculate_batch(batch_id)
        updated = self.repository.release_batch(batch_id, conclusion, actor)
        self.repository.append_audit("release", "deactivation", batch_id, actor, {
            "conclusion": conclusion, "batch_no": updated["batch_no"],
        })
        return self.get_deactivation(batch_id, role)

    def list_deactivations(self, role: str) -> list:
        self._view(role)
        return [self._enrich_deactivation(batch)
                for batch in self.repository.list_deactivation_batches()]

    def get_deactivation(self, batch_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        batch = self.repository.get_deactivation_batch(batch_id)
        return self._enrich_deactivation(batch)

    def _enrich_deactivation(self, batch: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(batch)
        result["permits"] = self.repository.list_batch_permits(batch["id"])
        result["pending_inspections"] = self.repository.list_batch_records(batch["id"])
        result["permit_count"] = len(result["permits"])
        result["pending_count"] = len(result["pending_inspections"])
        return result

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
