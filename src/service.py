from __future__ import annotations

from typing import Any, Dict, List, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_period, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, BATCH_ACTIVE, BATCH_ENTITY, CREATE_ROLES,
                    DEACTIVATION_ROLES, EFFECT_INSPECTION_FROZEN,
                    EFFECT_PERMIT_FROZEN, EFFECT_RECTIFICATION_OPEN, ENTITY,
                    EQUIPMENT_ENTITY, EQUIPMENT_ROLES, INSPECTION_KIND,
                    RECORD_CLOSE_ROLES, RECORD_ROLES, RECTIFICATION_KIND,
                    RELEASE_BASIS_KINDS, TERMINAL_STATES, TITLE, VIEW_ROLES,
                    completion_blockers, deactivation_key, escalation_required,
                    priority_score, release_decision, release_signature,
                    response_deadline_hours, role_for_transition,
                    validate_transition)


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
        equipment_id = self._resolve_equipment(payload)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, equipment_id)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
            "equipment_id": equipment_id,
        })
        return self._with_freeze(item)

    def _resolve_equipment(self, payload: Dict[str, Any]) -> Optional[int]:
        equipment_id = payload.get("equipment_id")
        equipment_ref = payload.get("equipment_ref")
        if equipment_id is not None:
            if isinstance(equipment_id, bool) or not isinstance(equipment_id, int):
                from .domain import ValidationError
                raise ValidationError("equipment_id必须是整数")
            return self.repository.get_equipment(equipment_id)["id"]
        if equipment_ref is not None:
            equipment_ref = require_text(equipment_ref, "equipment_ref", 100)
            return self.repository.find_equipment_by_ref(equipment_ref)["id"]
        return None

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
        if kind in RELEASE_BASIS_KINDS:
            self._recompute_release(item_id, actor)
        return record

    def close_record(self, item_id: int, record_id: int, actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_CLOSE_ROLES)
        actor = require_text(actor, "actor", 100)
        record = self.repository.get_record(record_id)
        if record["item_id"] != item_id:
            from .domain import NotFoundError
            raise NotFoundError("记录不存在")
        if self.repository.record_frozen(record_id):
            raise ConflictError("检查处于停用冻结中，禁止关闭")
        closed = self.repository.close_record(item_id, record_id)
        self.repository.append_audit("record_close", ENTITY, item_id, actor, {
            "record_id": record_id, "kind": record["kind"],
        })
        if record["kind"] in RELEASE_BASIS_KINDS:
            self._recompute_release(item_id, actor)
        return closed

    def _recompute_release(self, item_id: int, actor: str) -> Dict[str, Any]:
        basis = self.repository.release_basis(item_id)
        signature = release_signature(basis)
        open_rectifications = sum(
            1 for r in basis
            if r["kind"] == RECTIFICATION_KIND and r["status"] == "open")
        release, changed = self.repository.recompute_release(
            item_id, release_decision(open_rectifications), signature, actor)
        if changed:
            self.repository.append_audit("release", ENTITY, item_id, actor, {
                "release_id": release["id"], "decision": release["decision"],
                "open_rectifications": open_rectifications,
            })
        return release

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if self.repository.item_frozen(item_id):
            raise ConflictError("许可处于停用冻结中，禁止流转")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self._with_freeze(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._with_freeze(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self._with_freeze(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def list_releases(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_releases(item_id)

    def create_equipment(self, payload: Dict[str, Any], actor: str,
                         role: str) -> Dict[str, Any]:
        ensure_role(role, EQUIPMENT_ROLES)
        actor = require_text(actor, "actor", 100)
        facility = require_text(payload.get("facility"), "facility", 200)
        name = require_text(payload.get("name"), "name", 200)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        equipment = self.repository.create_equipment(facility, name,
                                                     external_ref, actor)
        self.repository.append_audit("equipment", EQUIPMENT_ENTITY,
                                     equipment["id"], actor, {
                                         "facility": facility, "name": name,
                                     })
        return equipment

    def list_equipment(self, role: str) -> list:
        self._view(role)
        return self.repository.list_equipment()

    def create_deactivation(self, payload: Dict[str, Any], actor: str,
                            role: str) -> Dict[str, Any]:
        ensure_role(role, DEACTIVATION_ROLES)
        actor = require_text(actor, "actor", 100)
        equipment_id = self._resolve_equipment(payload)
        if equipment_id is None:
            from .domain import ValidationError
            raise ValidationError("必须指定equipment_id或equipment_ref")
        equipment = self.repository.get_equipment(equipment_id)
        period_start, period_end = require_period(
            payload.get("period_start"), payload.get("period_end"))
        key = deactivation_key(equipment["id"], period_start, period_end)
        batch, reused = self.repository.ensure_deactivation_batch(
            equipment["id"], equipment["facility"], period_start, period_end,
            key, actor)
        if batch["status"] != BATCH_ACTIVE:
            effects = self._plan_effects(equipment["id"])
            batch, applied = self.repository.apply_deactivation_effects(
                batch["id"], effects)
            if applied:
                self.repository.append_audit("deactivation", BATCH_ENTITY,
                                             batch["id"], actor, {
                                                 "batch_no": batch["batch_no"],
                                                 "equipment_id": equipment["id"],
                                                 "period_start": period_start,
                                                 "period_end": period_end,
                                                 "effects": len(effects),
                                                 "retried": reused,
                                             })
        return self._handover(batch, reused)

    def _plan_effects(self, equipment_id: int) -> List[Dict[str, Any]]:
        effects: List[Dict[str, Any]] = []
        for item in self.repository.items_for_equipment(equipment_id):
            if item["status"] not in TERMINAL_STATES:
                effects.append({"item_id": item["id"], "record_id": 0,
                                "effect": EFFECT_PERMIT_FROZEN})
            for record in self.repository.list_records(item["id"]):
                if record["status"] != "open":
                    continue
                if record["kind"] == INSPECTION_KIND:
                    effects.append({"item_id": item["id"],
                                    "record_id": record["id"],
                                    "effect": EFFECT_INSPECTION_FROZEN})
                elif record["kind"] == RECTIFICATION_KIND:
                    effects.append({"item_id": item["id"],
                                    "record_id": record["id"],
                                    "effect": EFFECT_RECTIFICATION_OPEN})
        return effects

    def _handover(self, batch: Dict[str, Any], reused: bool) -> Dict[str, Any]:
        effects = self.repository.batch_effects(batch["id"])
        permits: Dict[int, Dict[str, Any]] = {}
        frozen_inspections: List[Dict[str, Any]] = []
        open_rectifications: List[Dict[str, Any]] = []
        for effect in effects:
            item_id = effect["item_id"]
            if item_id not in permits:
                item = self.repository.get_item(item_id)
                permits[item_id] = {
                    "id": item["id"], "title": item["title"],
                    "status": item["status"], "frozen": False,
                }
            if effect["effect"] == EFFECT_PERMIT_FROZEN:
                permits[item_id]["frozen"] = True
            elif effect["effect"] == EFFECT_INSPECTION_FROZEN:
                record = self.repository.get_record(effect["record_id"])
                frozen_inspections.append({
                    "record_id": record["id"], "item_id": item_id,
                    "detail": record["detail"], "status": record["status"],
                })
            elif effect["effect"] == EFFECT_RECTIFICATION_OPEN:
                record = self.repository.get_record(effect["record_id"])
                open_rectifications.append({
                    "record_id": record["id"], "item_id": item_id,
                    "detail": record["detail"], "status": record["status"],
                })
        facilities = [{
            "facility": batch["facility"],
            "permits": sorted(permits.values(), key=lambda p: p["id"]),
            "frozen_inspections": frozen_inspections,
            "open_rectifications": open_rectifications,
        }]
        return {"batch": batch, "reused": reused, "facilities": facilities}

    def get_deactivation(self, batch_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._handover(self.repository.get_batch(batch_id), True)

    def list_deactivations(self, role: str) -> list:
        self._view(role)
        return self.repository.list_batches()

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def _with_freeze(self, item: Dict[str, Any]) -> Dict[str, Any]:
        result = self.enrich(item)
        result["frozen"] = self.repository.item_frozen(item["id"])
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
