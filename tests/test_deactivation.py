import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.rules import (BATCH_ACTIVE, BATCH_PENDING, DECISION_HELD,
                       DECISION_RELEASED, RELEASE_INVALIDATED, RELEASE_VALID,
                       STATES, TRANSITION_ROLES)
from src.service import Service

PERIOD = {"period_start": "2026-10-01T00:00:00+00:00",
          "period_end": "2026-10-15T00:00:00+00:00"}


class DeactivationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.equipment = self.service.create_equipment(
            {"facility": "一号烧结设施", "name": "脱硫塔A",
             "external_ref": "EQ-1"}, "regulator", "inspector")
        self.item = self.service.create_item(
            {"title": "permit-1", "description": "permit under equipment",
             "severity": "high", "quantity": 5, "threshold": 10,
             "external_ref": "P-1", "equipment_id": self.equipment["id"]},
            "creator", "applicant")
        self.inspection = self.service.add_record(
            self.item["id"],
            {"kind": "inspection", "detail": "scheduled inspection",
             "status": "open", "external_ref": "INSP-1"},
            "recorder", "inspector")
        self.rectification = self.service.add_record(
            self.item["id"],
            {"kind": "rectification", "detail": "fix seal",
             "status": "open", "external_ref": "RECT-1"},
            "recorder", "inspector")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _submit(self, actor="regulator", role="inspector"):
        payload = dict(PERIOD, equipment_id=self.equipment["id"])
        return self.service.create_deactivation(payload, actor, role)

    def test_handover_groups_by_facility_and_freezes(self):
        result = self._submit()
        self.assertFalse(result["reused"])
        batch = result["batch"]
        self.assertEqual(batch["status"], BATCH_ACTIVE)
        self.assertTrue(batch["batch_no"].startswith("DB-"))
        self.assertEqual(len(result["facilities"]), 1)
        group = result["facilities"][0]
        self.assertEqual(group["facility"], "一号烧结设施")
        self.assertEqual([p["id"] for p in group["permits"]], [self.item["id"]])
        self.assertTrue(group["permits"][0]["frozen"])
        self.assertEqual([r["record_id"] for r in group["frozen_inspections"]],
                         [self.inspection["id"]])
        self.assertEqual([r["record_id"] for r in group["open_rectifications"]],
                         [self.rectification["id"]])
        # 冻结后许可禁止流转
        current = self.service.get_item(self.item["id"], "viewer")
        self.assertTrue(current["frozen"])
        with self.assertRaises(ConflictError):
            self.service.transition(self.item["id"], STATES[1],
                                    current["version"], "reviewer",
                                    TRANSITION_ROLES[STATES[1]][0])
        # 冻结后待执行检查禁止关闭，整改仍可关闭
        with self.assertRaises(ConflictError):
            self.service.close_record(self.item["id"], self.inspection["id"],
                                      "recorder", "inspector")
        closed = self.service.close_record(
            self.item["id"], self.rectification["id"], "recorder", "applicant")
        self.assertEqual(closed["status"], "closed")

    def test_repeated_submission_reuses_first_batch(self):
        first = self._submit(actor="regulator-a")
        second = self._submit(actor="regulator-b")
        self.assertTrue(second["reused"])
        self.assertEqual(second["batch"]["batch_no"], first["batch"]["batch_no"])
        self.assertEqual(second["batch"]["created_by"], "regulator-a")
        effects = self.repo.batch_effects(first["batch"]["id"])
        self.assertEqual(len(effects), 3)
        self.assertEqual(len(self.service.list_deactivations("viewer")), 1)

    def test_concurrent_submission_first_writer_wins(self):
        results, errors = [], []

        def submit(actor):
            try:
                results.append(self._submit(actor=actor))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=submit, args=(f"regulator-{i}",))
                   for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        batch_nos = {r["batch"]["batch_no"] for r in results}
        self.assertEqual(len(batch_nos), 1)
        creators = {r["batch"]["created_by"] for r in results}
        self.assertEqual(len(creators), 1)
        self.assertEqual(sorted(r["reused"] for r in results), [False, True])
        self.assertEqual(len(self.service.list_deactivations("viewer")), 1)

    def test_release_invalidated_and_recomputed_on_record_change(self):
        releases = self.service.list_releases(self.item["id"], "viewer")
        # 首次检查生成放行结论，随后未关闭整改使其失效并重算为暂扣
        self.assertEqual(len(releases), 2)
        self.assertEqual(releases[0]["decision"], DECISION_RELEASED)
        self.assertEqual(releases[0]["status"], RELEASE_INVALIDATED)
        self.assertEqual(releases[1]["decision"], DECISION_HELD)
        self.assertEqual(releases[1]["status"], RELEASE_VALID)
        # 关闭整改 → 旧放行失效，重算为放行
        self.service.close_record(self.item["id"], self.rectification["id"],
                                  "recorder", "applicant")
        releases = self.service.list_releases(self.item["id"], "viewer")
        self.assertEqual(len(releases), 3)
        self.assertEqual(releases[1]["status"], RELEASE_INVALIDATED)
        self.assertIsNotNone(releases[1]["invalidated_at"])
        self.assertEqual(releases[2]["status"], RELEASE_VALID)
        self.assertEqual(releases[2]["decision"], DECISION_RELEASED)
        # 晚到的检查 → 当前放行再次失效重算
        self.service.add_record(
            self.item["id"],
            {"kind": "inspection", "detail": "late inspection",
             "status": "open", "external_ref": "INSP-2"},
            "recorder", "inspector")
        releases = self.service.list_releases(self.item["id"], "viewer")
        self.assertEqual(len(releases), 4)
        self.assertEqual(releases[2]["status"], RELEASE_INVALIDATED)
        self.assertEqual(releases[3]["status"], RELEASE_VALID)
        # 无实际变化的记录类型不触发重算
        self.service.add_record(
            self.item["id"],
            {"kind": "evidence", "detail": "photo", "status": "open",
             "external_ref": "EV-9"},
            "recorder", "applicant")
        self.assertEqual(
            len(self.service.list_releases(self.item["id"], "viewer")), 4)

    def test_failed_write_keeps_batch_and_retries_with_same_number(self):
        original = self.repo.apply_deactivation_effects
        calls = {"n": 0}

        def failing(batch_id, effects):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated write failure")
            return original(batch_id, effects)

        with mock.patch.object(self.repo, "apply_deactivation_effects",
                               side_effect=failing):
            with self.assertRaises(RuntimeError):
                self._submit()
        pending = self.service.list_deactivations("viewer")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["status"], BATCH_PENDING)
        original_no = pending[0]["batch_no"]
        self.assertTrue(original_no.startswith("DB-"))
        # 重试沿用原批次编号
        retry = self._submit(actor="regulator-b")
        self.assertTrue(retry["reused"])
        self.assertEqual(retry["batch"]["batch_no"], original_no)
        self.assertEqual(retry["batch"]["status"], BATCH_ACTIVE)
        self.assertEqual(len(self.service.list_deactivations("viewer")), 1)
        effects = self.repo.batch_effects(retry["batch"]["id"])
        self.assertEqual(len(effects), 3)

    def test_validation_and_permissions(self):
        with self.assertRaises(PermissionDenied):
            self._submit(role="applicant")
        with self.assertRaises(ValidationError):
            self.service.create_deactivation(
                {"equipment_id": self.equipment["id"],
                 "period_start": "2026-10-15T00:00:00+00:00",
                 "period_end": "2026-10-01T00:00:00+00:00"},
                "regulator", "inspector")
        with self.assertRaises(ValidationError):
            self.service.create_deactivation(
                dict(PERIOD), "regulator", "inspector")
        with self.assertRaises(ValidationError):
            self.service.create_deactivation(
                {"equipment_id": self.equipment["id"],
                 "period_start": "not-a-date",
                 "period_end": "2026-10-01T00:00:00+00:00"},
                "regulator", "inspector")


if __name__ == "__main__":
    unittest.main()
