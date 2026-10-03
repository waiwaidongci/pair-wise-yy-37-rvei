import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.rules import TRANSITION_ROLES
from src.service import Service


class DeactivationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.service.register_device(
            {"device_ref": "DEV-1", "facility": "F1", "name": "治理设备A"},
            "admin", "compliance_manager")
        self.p1 = self.service.create_item(
            {"title": "许可1", "description": "desc", "severity": "high",
             "quantity": 5, "threshold": 10, "external_ref": "P1",
             "facility": "F1"},
            "creator", "applicant")
        self.p2 = self.service.create_item(
            {"title": "许可2", "description": "desc", "severity": "low",
             "quantity": 1, "threshold": 10, "external_ref": "P2",
             "facility": "F1"},
            "creator", "applicant")
        self.p3 = self.service.create_item(
            {"title": "许可3", "description": "desc", "severity": "low",
             "quantity": 1, "threshold": 10, "external_ref": "P3",
             "facility": "F2"},
            "creator", "applicant")
        self.service.add_record(
            self.p1["id"],
            {"kind": "rectification", "detail": "未关闭整改", "status": "open",
             "external_ref": "R1"},
            "rec", "applicant")
        self.service.add_record(
            self.p2["id"],
            {"kind": "inspection", "detail": "已完成检查", "status": "closed",
             "external_ref": "R2"},
            "rec", "applicant")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _submit(self, device="DEV-1", start="2026-10-01", end="2026-10-07",
                actor="sup"):
        return self.service.submit_deactivation(
            {"device_ref": device, "period_start": start, "period_end": end},
            actor, "compliance_manager")

    def test_submit_gathers_by_facility_and_freezes(self):
        batch, created = self._submit()
        self.assertTrue(created)
        self.assertEqual(batch["status"], "frozen")
        self.assertEqual(batch["facility"], "F1")
        permit_ids = {p["id"] for p in batch["permits"]}
        self.assertEqual(permit_ids, {self.p1["id"], self.p2["id"]})
        self.assertEqual(len(batch["pending_inspections"]), 1)
        self.assertEqual(batch["pending_inspections"][0]["item_id"], self.p1["id"])
        # 冻结期间许可不能转换
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.p1["id"], "submitted", self.p1["version"],
                "rev", TRANSITION_ROLES["submitted"][0])

    def test_duplicate_submit_uses_first_batch(self):
        b1, c1 = self._submit(actor="sup1")
        b2, c2 = self._submit(actor="sup2")
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(b1["id"], b2["id"])
        self.assertEqual(b1["batch_no"], b2["batch_no"])

    def test_concurrent_submit_first_arrival_wins(self):
        results = []
        barrier = threading.Barrier(2)

        def worker(actor):
            barrier.wait()
            try:
                b, created = self.service.submit_deactivation(
                    {"device_ref": "DEV-1", "period_start": "2026-11-01",
                     "period_end": "2026-11-07"},
                    actor, "compliance_manager")
                results.append((b["id"], created))
            except Exception:
                results.append((None, None))

        t1 = threading.Thread(target=worker, args=("supA",))
        t2 = threading.Thread(target=worker, args=("supB",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual([r[1] for r in results].count(True), 1)
        self.assertEqual([r[1] for r in results].count(False), 1)
        self.assertEqual(len({r[0] for r in results if r[0]}), 1)

    def test_record_change_invalidates_released_batch(self):
        batch, _ = self._submit()
        released = self.service.release_deactivation(
            batch["id"], {"conclusion": "同意临时停用"}, "sup",
            "compliance_manager")
        self.assertEqual(released["status"], "released")
        # 晚到的检查让旧放行失效
        self.service.add_record(
            self.p1["id"],
            {"kind": "inspection", "detail": "晚到的检查", "status": "open",
             "external_ref": "LATE-1"},
            "rec", "applicant")
        after = self.service.get_deactivation(batch["id"], "viewer")
        self.assertEqual(after["status"], "invalidated")
        self.assertIsNone(after["release_conclusion"])
        self.assertEqual(len(after["pending_inspections"]), 2)

    def test_retry_keeps_original_batch_and_number(self):
        batch, _ = self._submit()
        original_no = batch["batch_no"]
        retried = self.service.retry_deactivation(batch["id"], "sup",
                                                  "compliance_manager")
        self.assertEqual(retried["id"], batch["id"])
        self.assertEqual(retried["batch_no"], original_no)
        self.assertEqual(len(self.service.list_deactivations("viewer")), 1)

    def test_viewer_cannot_submit(self):
        with self.assertRaises(PermissionDenied):
            self.service.submit_deactivation(
                {"device_ref": "DEV-1", "period_start": "2026-10-01",
                 "period_end": "2026-10-07"},
                "viewer", "viewer")


if __name__ == "__main__":
    unittest.main()
