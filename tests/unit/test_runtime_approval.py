import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

spec = importlib.util.spec_from_file_location("runtime_approval", Path(__file__).resolve().parents[2] / "examples/runtime-security/approval.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 10
        self.store = module.ApprovalStore(str(Path(self.tmp.name) / "approvals.db"), {
            subject: {"credential_sha256": hashlib.sha256(token.encode()).hexdigest(), "role": role}
            for subject, token, role in [("alice", "a", "requester"), ("bob", "b", "reviewer"), ("eve", "e", "requester")]
        }, lambda: self.now)
        self.action = {"kind": "publish_training_notice", "notice": "훈련 공지"}
        self.identifier = self.store.propose("a", self.action)

    def test_pending_has_no_effect(self):
        with self.assertRaises(module.ApprovalDenied):
            self.store.execute("a", self.identifier, self.action)
        self.assertEqual(self.store.effect_count(), 0)

    def test_self_approval_denied(self):
        with self.assertRaises(module.ApprovalDenied):
            self.store.review("a", self.identifier, True)

    def test_normal_approval_allows_one_synthetic_effect(self):
        self.store.review("b", self.identifier, True)
        self.assertFalse(self.store.execute("a", self.identifier, self.action)["external_action_called"])
        with self.assertRaises(module.ApprovalDenied):
            self.store.execute("a", self.identifier, self.action)
        self.assertEqual(self.store.effect_count(), 1)

    def test_denied_or_expired_approval_has_no_effect(self):
        self.store.review("b", self.identifier, False)
        with self.assertRaises(module.ApprovalDenied):
            self.store.execute("a", self.identifier, self.action)
        fresh = self.store.propose("a", self.action)
        self.store.review("b", fresh, True)
        self.now += 301
        with self.assertRaises(module.ApprovalDenied):
            self.store.execute("a", fresh, self.action)
        self.assertEqual(self.store.effect_count(), 0)

    def test_approval_bound_to_requester_and_payload(self):
        self.store.review("b", self.identifier, True)
        for key, action in [("e", self.action), ("a", {**self.action, "notice": "다른 공지"})]:
            with self.assertRaises(module.ApprovalDenied):
                self.store.execute(key, self.identifier, action)
        self.assertEqual(self.store.effect_count(), 0)

    def test_parallel_consumption_is_single_use(self):
        self.store.review("b", self.identifier, True)
        def execute(_):
            try:
                return self.store.execute("a", self.identifier, self.action)
            except module.ApprovalDenied:
                return None
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(execute, range(4)))
        self.assertEqual(sum(x is not None for x in results), 1)
        self.assertEqual(self.store.effect_count(), 1)

    def test_browser_metadata_cannot_self_approve(self):
        with self.assertRaises(module.ApprovalDenied):
            self.store.propose("a", {**self.action, "approved": True})
        with self.assertRaises(module.ApprovalDenied):
            self.store.propose("unknown", self.action)


if __name__ == "__main__":
    unittest.main()
