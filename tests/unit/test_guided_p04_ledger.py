"""P04 persistent lifecycle and call coordinator tests, no AWS."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

GATEWAY = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
sys.path.insert(0, str(GATEWAY))
try:
    from p04_contract import expected_arguments
    from p04_ledger import GuardrailLedger, LedgerError
    from p04_invocation import Invocation, InvocationError
finally:
    sys.path.remove(str(GATEWAY))


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = 1000.0
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.ledger = GuardrailLedger(self.path, now=lambda: self.clock)
        self.body = {"operation": "converse", "text": "hello"}
        self.guardrail = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.mode = "aws"
        self.grant = self.register()
        self.payload = expected_arguments(self.body, self.guardrail)
        self.resource = "c" * 64
        self.response = {"ResponseMetadata": {"RequestId": "native-" + uuid4().hex}, "result": "fixture"}
        self.calls = []
        self.failure = False
        self.changed_after = False
        self.invocation = Invocation(self.ledger, self.backend, lambda: self.resource)

    def register(self):
        return self.ledger.register(self.suite, self.execution, "a" * 64, "b" * 64,
                                    "c" * 64, self.mode, self.body, self.guardrail)

    def backend(self, operation, payload):
        self.calls.append((operation, payload))
        if self.failure:
            raise RuntimeError("must-not-leak-provider-details")
        if self.changed_after:
            self.resource = "d" * 64
        return self.response

    def invoke(self, **changes):
        values = dict(token=self.grant["capability"], suite_id=self.suite,
                      execution_id=self.execution, operation="converse", payload=self.payload)
        values.update(changes)
        return self.invocation.invoke(**values)

    def test_call_close_reopen_and_read_only_evidence(self):
        result = self.invoke()
        self.assertEqual(result["response"], self.response)
        closed = self.ledger.close(self.execution)
        reopened = GuardrailLedger(self.path, now=lambda: self.clock)
        before = reopened.read(self.execution)
        self.assertEqual(before, reopened.read(self.execution))
        self.assertTrue(before["closed"])
        self.assertEqual(before["calls"][0]["request"], self.payload)
        self.assertEqual(before["calls"][0]["provider_request_id"], self.response["ResponseMetadata"]["RequestId"])
        self.assertEqual(reopened.close(self.execution), closed)
        self.assertNotIn(self.grant["capability"], json.dumps(before))
        self.assertNotIn("capability_hash", before)
        self.assertNotIn("task_completed", before)
        with self.assertRaises(LedgerError):
            self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_registered_but_unused_execution_can_close_without_claiming_pass(self):
        self.ledger.close(self.execution)
        saved = self.ledger.read(self.execution)
        self.assertEqual(saved["calls"], [])
        self.assertTrue(saved["closed"])
        self.assertNotIn("security_verdict", saved)

    def test_other_token_suite_expired_and_backwards_clock_do_not_call(self):
        for changes in ({"token": "wrong-" * 10}, {"suite_id": str(uuid4())}):
            with self.assertRaises(LedgerError):
                self.invoke(**changes)
        for stamp in (999, 1180):
            self.clock = stamp
            with self.assertRaises(LedgerError):
                self.invoke()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.ledger.read(self.execution)["calls"], [])

    def test_duplicate_registration_does_not_replace_record(self):
        before = self.ledger.read(self.execution)
        with self.assertRaises(LedgerError):
            self.register()
        self.assertEqual(self.ledger.read(self.execution), before)

    def test_two_concurrent_invocations_dispatch_only_once(self):
        def attempt():
            try:
                self.invoke()
                return "called"
            except LedgerError:
                return "rejected"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(2)))
        self.assertCountEqual(outcomes, ["called", "rejected"])
        self.assertEqual(len(self.calls), 1)

    def test_wrong_policy_is_recorded_as_error_without_dispatch(self):
        self.payload["guardrailConfig"]["guardrailIdentifier"] = "other"
        with self.assertRaises(InvocationError):
            self.invoke()
        self.ledger.close(self.execution)
        call = self.ledger.read(self.execution)["calls"][0]
        self.assertEqual(call["state"], "error")
        self.assertIsNone(call["dispatched_at"])
        self.assertEqual(self.calls, [])
        with self.assertRaises(LedgerError):
            self.invoke()

    def test_changed_resource_before_call_stops_dispatch(self):
        self.resource = "d" * 64
        with self.assertRaises(InvocationError):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.ledger.read(self.execution)["calls"][0]["dispatched_at"])

    def test_failure_after_dispatch_preserves_attempt_not_false_zero(self):
        self.failure = True
        with self.assertRaisesRegex(InvocationError, "^P04 provider invocation failed$"):
            self.invoke()
        self.ledger.close(self.execution)
        call = self.ledger.read(self.execution)["calls"][0]
        self.assertEqual(call["state"], "error")
        self.assertIsNotNone(call["dispatched_at"])
        self.assertIsNone(call["response"])
        self.assertEqual(len(self.calls), 1)

    def test_changed_resource_after_call_is_error(self):
        self.changed_after = True
        with self.assertRaises(InvocationError):
            self.invoke()
        call = self.ledger.read(self.execution)["calls"][0]
        self.assertEqual(call["state"], "error")
        self.assertIsNotNone(call["dispatched_at"])
        self.assertEqual(len(self.calls), 1)

    def test_pending_call_cannot_be_closed_or_resumed_after_restart(self):
        self.ledger.reserve(self.grant["capability"], self.suite, self.execution, "converse", self.payload)
        reopened = GuardrailLedger(self.path, now=lambda: self.clock)
        with self.assertRaises(LedgerError):
            reopened.close(self.execution)
        with self.assertRaises(LedgerError):
            self.invoke()
        self.assertEqual(reopened.read(self.execution)["calls"][0]["state"], "pending")

    def test_success_without_dispatch_and_late_finish_are_rejected(self):
        self.ledger.reserve(self.grant["capability"], self.suite, self.execution, "converse", self.payload)
        with self.assertRaises(LedgerError):
            self.ledger.finish(self.execution, self.response)
        self.ledger.dispatch(self.execution)
        self.clock = 1180
        with self.assertRaises(LedgerError):
            self.ledger.finish(self.execution, self.response)
        with self.assertRaises(LedgerError):
            self.ledger.close(self.execution)

    def test_aws_response_without_native_id_is_not_complete(self):
        self.response = {"result": "no native evidence"}
        with self.assertRaises(InvocationError):
            self.invoke()
        self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "error")

    def test_contract_response_is_not_relabelled_native_aws_evidence(self):
        self.execution, self.mode = str(uuid4()), "contract"
        self.grant = self.register()
        self.invoke()
        saved = self.ledger.read(self.execution)
        self.assertEqual(saved["provider_mode"], "contract")
        self.assertIsNone(saved["calls"][0]["provider_request_id"])
        self.assertEqual(saved["calls"][0]["response"], self.response)

    def test_native_id_reuse_cannot_finish_second_execution(self):
        self.invoke()
        self.execution = str(uuid4())
        self.grant = self.register()
        with self.assertRaises(InvocationError):
            self.invoke()
        self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "error")

    def test_missing_or_oversized_response_is_error_not_an_empty_success(self):
        for response in (None, [], {"text": "x" * 33000}):
            self.execution = str(uuid4())
            self.grant = self.register()
            self.response = response
            with self.assertRaises(InvocationError):
                self.invoke()
            self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "error")

    def test_invalid_registration_and_request_do_not_create_call_records(self):
        for mode in ("unknown", None):
            self.mode = mode
            with self.assertRaises(LedgerError):
                self.register()
        for payload in ([], {"text": "x" * 33000}, {"temperature": float("nan")}):
            with self.assertRaises(LedgerError):
                self.invoke(payload=payload)
        self.assertEqual(self.ledger.read(self.execution)["calls"], [])

    def test_error_finish_cannot_precede_dispatch(self):
        self.ledger.reserve(self.grant["capability"], self.suite, self.execution, "converse", self.payload)
        self.clock += 10
        self.ledger.dispatch(self.execution)
        self.clock -= 5
        with self.assertRaises(LedgerError):
            self.ledger.finish(self.execution)
        self.assertEqual(self.ledger.read(self.execution)["calls"][0]["state"], "pending")


if __name__ == "__main__":
    unittest.main()
