"""P12 capability state machine only; no provider, network, NeMo or AWS calls."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p12_capabilities.py"
spec = importlib.util.spec_from_file_location("p12_capabilities", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "gateway.sqlite3"
        self.clock = [1000.0]
        self.store = module.CapabilityStore(self.path, now=lambda: self.clock[0])
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.issued = self.store.issue(self.suite, [self.execution])
        self.grant = self.issued["grants"][0]
        self.provider = {"provider_request_id": "fixture-provider-id", "text": "No", "stop_reason": "end_turn",
                         "usage": {"inputTokens": 5, "outputTokens": 1, "totalTokens": 6}}

    def reserve(self, grant=None, **updates):
        grant = grant or self.grant
        fields = {key: grant[key] for key in ("suite_id", "execution_id", "role", "model")}
        return self.store.reserve(grant["capability"], **{**fields, "request_digest": "a" * 64, **updates})

    def assert_error(self, status, callback):
        with self.assertRaises(module.GrantError) as caught:
            callback()
        self.assertEqual(caught.exception.status, status)

    def test_four_distinct_roles_no_raw_tokens_persisted(self):
        grants = self.issued["grants"]
        self.assertEqual({grant["role"] for grant in grants}, set(module.ROLES))
        self.assertEqual(len({grant["capability"] for grant in grants}), 4)
        self.assertEqual(len({grant["model"] for grant in grants}), 4)
        for grant in grants:
            self.assertNotIn(grant["capability"].encode(), self.path.read_bytes())
            self.assertNotIn(grant["capability"], json.dumps(self.store.ledger(self.suite)))

    def test_wrong_role_model_suite_execution_and_token_rejected(self):
        for updates in ({"role": "main"}, {"model": module.MARKERS["main"]},
                        {"suite_id": str(uuid4())}, {"execution_id": str(uuid4())}):
            self.assert_error(403, lambda: self.reserve(**updates))
        self.assert_error(401, lambda: self.store.reserve("invalid" * 8, suite_id=self.suite,
                          execution_id=self.execution, role="main", model=module.MARKERS["main"], request_digest="a" * 64))
        self.assertTrue(all(row["state"] == "issued" for row in self.store.ledger(self.suite)["grants"]))

    def test_atomic_concurrent_reservation_has_exactly_one_winner(self):
        def attempt(_):
            try:
                self.reserve()
                return 200
            except module.GrantError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count(200), 1)
        self.assertEqual(results.count(409), 7)

    def test_expired_or_backwards_clock_cannot_reserve(self):
        for value in (999.0, 1180.0, 2000.0):
            self.clock[0] = value
            self.assert_error(403, self.reserve)

    def test_pending_survives_restart_and_prevents_false_closure(self):
        self.reserve()
        self.store = module.CapabilityStore(self.path, now=lambda: self.clock[0])
        self.assert_error(409, lambda: self.store.close(self.suite))
        self.assert_error(409, self.reserve)
        self.store.fail(self.grant["capability"])
        self.store.close(self.suite)
        ledger = self.store.ledger(self.suite)
        self.assertEqual([row["state"] for row in ledger["grants"]].count("error"), 1)
        self.assertEqual([row["state"] for row in ledger["grants"]].count("closed_unused"), 3)
        self.assertNotIn("task_completed", ledger)

    def test_completion_and_closure_are_persistent_without_response_text(self):
        self.reserve()
        result = self.store.complete(self.grant["capability"], self.provider)
        self.assertTrue(result["classifier_schema_valid"])
        self.assertEqual(result["classifier_answer"], "No")
        self.assert_error(409, lambda: self.store.complete(self.grant["capability"], self.provider))
        first_close = self.store.close(self.suite)
        self.clock[0] += 1
        self.assertEqual(self.store.close(self.suite), first_close)
        before = self.store.ledger(self.suite)
        self.assertEqual(module.CapabilityStore(self.path).ledger(self.suite), before)
        self.assert_error(409, lambda: self.reserve(self.issued["grants"][-1]))

    def test_malformed_classifier_is_recorded_not_normal_block(self):
        self.reserve()
        result = self.store.complete(self.grant["capability"], {**self.provider, "text": "Yes\n"})
        self.assertFalse(result["classifier_schema_valid"])
        self.assertIsNone(result["classifier_answer"])
        self.assertNotIn("Yes\\n", json.dumps(self.store.ledger(self.suite)))

    def test_main_text_is_hashed_and_not_treated_as_classifier(self):
        grant = self.issued["grants"][-1]
        self.reserve(grant)
        result = self.store.complete(grant["capability"], {**self.provider, "text": "synthetic-private-main-text"})
        self.assertNotIn("classifier_answer", result)
        self.assertNotIn(b"synthetic-private-main-text", self.path.read_bytes())

    def test_incomplete_or_reused_provider_evidence_cannot_complete(self):
        self.reserve()
        for updates in ({"provider_request_id": ""}, {"text": ""}, {"stop_reason": "unknown"},
                        {"usage": {"inputTokens": 5, "outputTokens": True, "totalTokens": 6}},
                        {"usage": {"inputTokens": 5, "outputTokens": 1, "totalTokens": 7}}):
            self.assert_error(502, lambda: self.store.complete(self.grant["capability"], {**self.provider, **updates}))
        self.store.complete(self.grant["capability"], self.provider)
        other = self.issued["grants"][1]
        self.reserve(other)
        self.assert_error(409, lambda: self.store.complete(other["capability"], self.provider))
        self.assert_error(409, lambda: self.store.close(self.suite))

    def test_bad_registration_and_unknown_suite_are_rejected(self):
        for ids in ([], [self.execution, self.execution], [str(uuid4()) for _ in range(33)], ["bad"]):
            self.assert_error(422, lambda: self.store.issue(str(uuid4()), ids))
        self.assert_error(409, lambda: self.store.issue(self.suite, [self.execution]))
        self.assert_error(404, lambda: self.store.ledger(str(uuid4())))
        self.assert_error(404, lambda: self.store.close(str(uuid4())))


if __name__ == "__main__":
    unittest.main(verbosity=2)
