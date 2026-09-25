"""Local SQLite lifecycle tests; no AWS or learner completion claims."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p02_ledger.py"
spec = importlib.util.spec_from_file_location("p02_ledger", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.clock = [1000.0]
        self.store = module.DocumentLedger(self.path, now=lambda: self.clock[0])
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.grant = self.store.register(self.suite, self.execution, "a" * 64, "b" * 64)

    def reserve(self, operation="store_source", **updates):
        args = dict(token=self.grant["capability"], suite_id=self.suite,
                    execution_id=self.execution, operation=operation, request_digest="c" * 64)
        return self.store.reserve(**{**args, **updates})

    def error(self, status, callback):
        with self.assertRaises(module.LedgerError) as caught:
            callback()
        self.assertEqual(caught.exception.status, status)

    def test_closed_zero_calls_is_explicit_and_persistent(self):
        self.store.close(self.execution)
        receipt = self.store.read(self.execution)
        self.assertTrue(receipt["closed"])
        self.assertEqual(receipt["calls"], [])
        self.assertEqual(receipt, module.DocumentLedger(self.path).read(self.execution))
        self.assertNotIn("task_completed", receipt)
        self.assertNotIn(self.grant["capability"], json.dumps(receipt))
        self.assertNotIn(self.grant["capability"].encode(), self.path.read_bytes())
        self.error(409, self.reserve)

    def test_pending_cannot_be_closed_even_after_expiry_or_restart(self):
        self.reserve()
        self.store = module.DocumentLedger(self.path, now=lambda: self.clock[0])
        self.clock[0] = 1400
        self.error(409, lambda: self.store.close(self.execution))
        self.error(409, lambda: self.reserve("embed"))
        self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "pending")

    def test_two_successes_preserve_actual_order_and_provider_ids(self):
        for operation, request_id in (("store_source", "s3-test"), ("embed", "titan-test")):
            self.reserve(operation)
            self.store.finish(self.execution, operation, {"provider_request_id": request_id})
        closed = self.store.close(self.execution)
        self.clock[0] += 1
        self.assertEqual(closed, self.store.close(self.execution))
        receipt = self.store.read(self.execution)
        self.assertEqual([c["sequence"] for c in receipt["calls"]], [1, 2])
        self.assertEqual([c["provider_request_id"] for c in receipt["calls"]], ["s3-test", "titan-test"])
        self.assertEqual(receipt["source_digest"], "a" * 64)
        self.assertEqual(receipt["runner_digest"], "b" * 64)

    def test_wrong_order_is_observed_not_silently_repaired(self):
        self.reserve("embed")
        self.store.finish(self.execution, "embed", {"provider_request_id": "titan-first"})
        self.reserve()
        self.assertEqual([c["operation"] for c in self.store.read(self.execution)["calls"]], ["embed", "store_source"])

    def test_failure_is_terminal_and_preserves_attempt(self):
        self.reserve()
        self.store.finish(self.execution, "store_source")
        self.error(409, lambda: self.reserve("embed"))
        self.store.close(self.execution)
        calls = self.store.read(self.execution)["calls"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["state"], "error")
        self.assertIsNone(calls[0]["response"])

    def test_duplicate_or_concurrent_operation_has_one_winner(self):
        def attempt(_):
            try:
                self.reserve()
                return 200
            except module.LedgerError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count(200), 1)
        self.assertEqual(results.count(409), 7)

    def test_credentials_binding_and_expiry(self):
        self.error(401, lambda: self.reserve(token="wrong" * 10))
        self.error(403, lambda: self.reserve(suite_id=str(uuid4())))
        for stamp in (999, 1180, float("nan")):
            self.clock[0] = stamp
            self.error(409, self.reserve)
        self.assertEqual(self.store.read(self.execution)["calls"], [])

    def test_invalid_completion_remains_pending(self):
        self.reserve()
        for response in ({}, [], {"provider_request_id": "x", "norm": float("nan")},
                         {"provider_request_id": "x", "data": "x" * 16384}):
            self.error(502, lambda: self.store.finish(self.execution, "store_source", response))
        self.error(409, lambda: self.store.close(self.execution))

    def test_reused_provider_id_and_repeated_finish_are_rejected(self):
        self.reserve()
        response = {"provider_request_id": "same-id"}
        self.store.finish(self.execution, "store_source", response)
        self.error(409, lambda: self.store.finish(self.execution, "store_source", response))
        self.reserve("embed")
        self.error(409, lambda: self.store.finish(self.execution, "embed", response))
        self.error(409, lambda: self.store.close(self.execution))

    def test_registration_duplicate_unknown_and_invalid_binding(self):
        self.error(409, lambda: self.store.register(self.suite, self.execution, "a" * 64, "b" * 64))
        self.error(422, lambda: self.store.register(self.suite, str(uuid4()), "not-a-digest", "b" * 64))
        self.error(422, lambda: self.store.register("bad", str(uuid4()), "a" * 64, "b" * 64))
        self.error(404, lambda: self.store.read(str(uuid4())))
        self.error(404, lambda: self.store.close(str(uuid4())))

    def test_backwards_completion_and_closure_are_rejected(self):
        self.reserve()
        self.clock[0] = 999
        self.error(409, lambda: self.store.finish(self.execution, "store_source"))
        self.clock[0] = 1001
        self.store.finish(self.execution, "store_source")
        self.clock[0] = 1000
        self.error(409, lambda: self.store.close(self.execution))


if __name__ == "__main__":
    unittest.main(verbosity=2)
