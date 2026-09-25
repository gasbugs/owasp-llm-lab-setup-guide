"""Local SQLite lifecycle tests; no AWS or learner completion claims."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p03_ledger.py"
spec = importlib.util.spec_from_file_location("p03_ledger", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.clock = [1000.0]
        self.store = module.SearchLedger(self.path, now=lambda: self.clock[0])
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.grant = self.store.register(self.suite, self.execution, "a" * 64, "b" * 64, "h03-current")

    def reserve(self, operation="job_status", **updates):
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
        self.assertEqual(receipt, module.SearchLedger(self.path).read(self.execution))
        self.assertNotIn("task_completed", receipt)
        self.assertNotIn(self.grant["capability"], json.dumps(receipt))
        self.assertNotIn(self.grant["capability"].encode(), self.path.read_bytes())
        self.error(409, self.reserve)

    def test_pending_cannot_be_closed_even_after_expiry_or_restart(self):
        self.reserve()
        self.store = module.SearchLedger(self.path, now=lambda: self.clock[0])
        self.clock[0] = 1400
        self.error(409, lambda: self.store.close(self.execution))
        self.error(409, lambda: self.reserve("retrieve"))
        self.assertEqual(self.store.read(self.execution)["calls"][0]["state"], "pending")

    def test_two_successes_preserve_actual_order_and_observation_ids(self):
        for operation, request_id in (("job_status", "s3-test"), ("retrieve", "titan-test")):
            self.reserve(operation)
            self.store.finish(self.execution, operation, {"observation_id": request_id})
        closed = self.store.close(self.execution)
        self.clock[0] += 1
        self.assertEqual(closed, self.store.close(self.execution))
        receipt = self.store.read(self.execution)
        self.assertEqual([c["sequence"] for c in receipt["calls"]], [1, 2])
        self.assertEqual([c["observation_id"] for c in receipt["calls"]], ["s3-test", "titan-test"])
        self.assertEqual(receipt["source_digest"], "a" * 64)
        self.assertEqual(receipt["runner_digest"], "b" * 64)

    def test_wrong_order_is_observed_not_silently_repaired(self):
        self.reserve("retrieve")
        self.store.finish(self.execution, "retrieve", {"observation_id": "titan-first"})
        self.reserve()
        self.assertEqual([c["operation"] for c in self.store.read(self.execution)["calls"]], ["retrieve", "job_status"])

    def test_failure_is_terminal_and_preserves_attempt(self):
        self.reserve()
        self.store.finish(self.execution, "job_status")
        self.error(409, lambda: self.reserve("retrieve"))
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
        for response in ({}, [], {"observation_id": "x", "norm": float("nan")},
                         {"observation_id": "x", "data": "x" * 16384}):
            self.error(502, lambda: self.store.finish(self.execution, "job_status", response))
        self.error(409, lambda: self.store.close(self.execution))

    def test_reused_observation_id_and_repeated_finish_are_rejected(self):
        self.reserve()
        response = {"observation_id": "same-id"}
        self.store.finish(self.execution, "job_status", response)
        self.error(409, lambda: self.store.finish(self.execution, "job_status", response))
        self.reserve("retrieve")
        self.error(409, lambda: self.store.finish(self.execution, "retrieve", response))
        self.error(409, lambda: self.store.close(self.execution))

    def test_registration_duplicate_unknown_and_invalid_binding(self):
        self.error(409, lambda: self.store.register(self.suite, self.execution, "a" * 64, "b" * 64, "h03-current"))
        self.error(422, lambda: self.store.register(self.suite, str(uuid4()), "not-a-digest", "b" * 64, "h03-current"))
        self.error(422, lambda: self.store.register("bad", str(uuid4()), "a" * 64, "b" * 64, "h03-current"))
        self.error(404, lambda: self.store.read(str(uuid4())))
        self.error(404, lambda: self.store.close(str(uuid4())))

    def test_backwards_completion_and_closure_are_rejected(self):
        self.reserve()
        self.clock[0] = 999
        self.error(409, lambda: self.store.finish(self.execution, "job_status"))
        self.clock[0] = 1001
        self.store.finish(self.execution, "job_status")
        self.clock[0] = 1000
        self.error(409, lambda: self.store.close(self.execution))


    def test_current_job_binding_and_invalid_registration(self):
        for value in (self.grant, self.store.read(self.execution)):
            self.assertEqual(value["practice_id"], "P03")
            self.assertEqual(value["activity_id"], "H03")
            self.assertEqual(value["contract_version"], "p03-search-v1")
        self.assertEqual(self.grant["current_job_id"], "h03-current")
        self.assertEqual(self.store.read(self.execution)["current_job_id"], "h03-current")
        for job in ("", "job/other", "a" * 129, "작업", None):
            self.error(422, lambda: self.store.register(
                self.suite, str(uuid4()), "a" * 64, "b" * 64, job))

    def test_unregistered_execution_is_not_zero_calls(self):
        self.error(404, lambda: self.store.read(str(uuid4())))
        self.assertFalse(self.store.read(self.execution)["closed"])
        self.store.close(self.execution)
        self.assertTrue(self.store.read(self.execution)["closed"])

    def test_native_request_identity_cannot_be_reused_as_a_new_observation(self):
        self.reserve()
        self.store.finish(self.execution, "job_status", {
            "observation_id": "local-status", "provider_request_id": "native-id"})
        self.reserve("retrieve")
        self.error(409, lambda: self.store.finish(self.execution, "retrieve", {
            "observation_id": "local-retrieve", "provider_request_id": "native-id"}))
        self.assertEqual(self.store.read(self.execution)["calls"][1]["state"], "pending")

if __name__ == "__main__":
    unittest.main(verbosity=2)
