"""Behavioral tests for durable gateway admission, including concurrent clients."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/bedrock-gateway/gateway_operations.py"
spec = importlib.util.spec_from_file_location("gateway_operations", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
GatewayOperations, PolicyDenied = module.GatewayOperations, module.PolicyDenied


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.policy = {"window_seconds": 60, "clients": {
            name: {"credential_sha256": hashlib.sha256(key.encode()).hexdigest(),
                   "models": ["nova"], "requests": 3, "output_tokens": 100,
                   "max_output_tokens": 60, "max_input_bytes": 16}
            for name, key in [("team-a", "test-credential-a"), ("team-b", "test-credential-b")]}}
        (self.path / "policy.json").write_text(json.dumps(self.policy))
        self.now = 120
        self.ops = self.reopen()

    def reopen(self):
        return GatewayOperations(str(self.path / "policy.json"), str(self.path / "usage.db"), lambda: self.now)

    def test_authentication_cannot_select_another_principal(self):
        self.assertEqual(self.ops.authenticate("test-credential-a"), "team-a")
        with self.assertRaises(PolicyDenied):
            self.ops.authenticate("team-b")

    def test_model_and_input_rejection_do_not_consume_quota(self):
        for model, text, cap in [("other", "ok", 5), ("nova", "가" * 6, 5), ("nova", "ok", 61)]:
            with self.assertRaises(PolicyDenied):
                self.ops.admit("team-a", model, text, cap)
        self.assertEqual(self.ops.usage("team-a")["requests"], 0)

    def test_settlement_releases_only_unused_output_reservation(self):
        first = self.ops.admit("team-a", "nova#self_check", "ok", 60)
        with self.assertRaises(PolicyDenied):
            self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.settle(first, 12, 20)
        self.ops.admit("team-a", "nova", "ok", 60)
        usage = self.ops.usage("team-a")
        self.assertEqual((usage["output_committed"], usage["input_tokens"], usage["output_reserved"]), (80, 12, 60))

    def test_parallel_reservations_never_oversubscribe(self):
        def admit(_):
            try:
                return self.reopen().admit("team-a", "nova", "ok", 60)
            except PolicyDenied:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted = [x for x in pool.map(admit, range(8)) if x]
        self.assertEqual(len(accepted), 1)

    def test_restart_and_unknown_provider_result_keep_reservation(self):
        first = self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.uncertain(first)
        ops = self.reopen()
        with self.assertRaises(PolicyDenied):
            ops.admit("team-a", "nova", "ok", 60)
        self.assertEqual(ops.usage("team-a")["output_reserved"], 60)

    def test_credentials_have_independent_budgets(self):
        self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.admit("team-b", "nova", "ok", 60)
        self.assertEqual(self.ops.usage("team-b")["requests"], 1)

    def test_request_limit_and_window_rollover(self):
        for _ in range(3):
            self.ops.admit("team-a", "nova", "ok", 1)
        with self.assertRaises(PolicyDenied) as error:
            self.ops.admit("team-a", "nova", "ok", 1)
        self.assertEqual(error.exception.reason, "request-quota")
        self.now = 180
        self.ops.admit("team-a", "nova", "ok", 1)
        self.assertEqual(self.ops.usage("team-a")["requests"], 1)

    def test_late_settlement_stays_in_original_window(self):
        previous = self.ops.admit("team-a", "nova", "ok", 60)
        self.now = 180
        self.assertEqual(self.ops.usage("team-a")["requests"], 0)
        current = self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.settle(previous, 12, 20)
        usage = self.reopen().usage("team-a")
        self.assertEqual((usage["window_start"], usage["requests"], usage["output_reserved"]), (180, 1, 60))
        self.assertEqual(usage["output_tokens"], 0)
        with self.assertRaises(PolicyDenied):
            self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.settle(current, 8, 10)
        self.now = 120
        previous_usage = self.reopen().usage("team-a")
        self.assertEqual((previous_usage["requests"], previous_usage["output_tokens"]), (1, 20))

    def test_duplicate_settlement_cannot_refund_twice(self):
        first = self.ops.admit("team-a", "nova", "ok", 60)
        self.ops.settle(first, 10, 20)
        with self.assertRaises(ValueError):
            self.ops.settle(first, 0, 0)
        self.assertEqual(self.ops.usage("team-a")["output_committed"], 20)

    def test_invalid_usage_does_not_release_reserved_tokens(self):
        first = self.ops.admit("team-a", "nova", "ok", 60)
        for values in [(1, 61), (-1, 0), (1, True)]:
            with self.assertRaises(ValueError):
                self.ops.settle(first, *values)
        self.assertEqual(self.ops.usage("team-a")["output_reserved"], 60)

    def test_duplicate_credential_configuration_fails_closed(self):
        self.policy["clients"]["team-b"]["credential_sha256"] = self.policy["clients"]["team-a"]["credential_sha256"]
        (self.path / "policy.json").write_text(json.dumps(self.policy))
        with self.assertRaises(ValueError):
            self.reopen()


if __name__ == "__main__":
    unittest.main()
