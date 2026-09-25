"""P04 independent evidence binding, including malformed and stale records."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

import httpx
import test_guided_p04_workflow as flow
from test_guided_p04_suites import case_module

VERIFIER = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-evidence-verifier"


def load(name):
    spec = importlib.util.spec_from_file_location(name, VERIFIER / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


results = load("p04_results")
with patch.dict(sys.modules, {"p04_results": results}):
    collector = load("p04_verification")


class BindingTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ledger = flow.gateway.GuardrailLedger(Path(temp.name) / "ledger.sqlite3", now=lambda: 1000)

    def sample(self, index=0, mode="contract"):
        self.case = case_module.cases()[index]
        self.resources = {"provider_mode": mode, "guardrail": {
            "guardrailIdentifier": "p04fixture" if mode == "aws" else "p04contract", "guardrailVersion": "DRAFT"},
            "guardrail_arn": "arn:aws:bedrock:us-east-1:000000000000:guardrail/p04fixture" if mode == "aws" else None,
            "policy_digest": "c" * 64}
        self.suite, self.execution = str(uuid4()), str(uuid4())
        actual_mode = mode if self.case["backend"] == "provider" else "contract"
        grant = self.ledger.register(self.suite, self.execution, "a" * 64, "b" * 64,
            results.sha(self.resources), actual_mode, self.case["body"], self.resources["guardrail"])
        local_calls = []
        worker = {"source_digest": "a" * 64, "execution_status": self.case["expected"], "calls": local_calls}
        if self.case["expected"] != "rejected":
            operation = self.case["body"]["operation"]
            request = flow.gateway.expected_arguments(self.case["body"], self.resources["guardrail"])
            self.ledger.reserve(grant["capability"], self.suite, self.execution, operation, request)
            def audit(phase):
                self.ledger.policy_audit(self.execution, phase, {'scope': 'aws-policy-audit',
                    'started_at': 1000, 'observed_at': 1000, 'resources': self.resources,
                    'aws_request_ids': [uuid4().hex for _ in range(3)]})
            if actual_mode == 'aws':
                audit('before')
            self.ledger.dispatch(self.execution)
            response = None if self.case["provider_error"] else {"fixture": "not Guardrail effectiveness"}
            if response is not None and actual_mode == "aws":
                response["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": "native-" + uuid4().hex}
                audit('after')
            self.ledger.finish(self.execution, response)
            local = {"operation": operation, "request_digest": results.sha(request),
                     "state": "error" if response is None else "complete", "http_status": 502 if response is None else 200}
            if response is not None:
                local["response_digest"] = results.sha(response)
                worker["result"] = response
            local_calls.append(local)
        closure = self.ledger.close(self.execution)
        self.record = self.ledger.read(self.execution)
        self.receipt = {"suite_id": self.suite, "execution_id": self.execution, "source_digest": "a" * 64,
            "runner_digest": "b" * 64, "lifecycle_status": "finished", "started_at": 1000,
            "closure": {"state": "closed", "closed_at": closure["closed_at"]}, "execution": worker}

    def verify(self, **changes):
        options = {"suite_id": self.suite, "execution_id": self.execution, "source_digest": "a" * 64,
                   "runner_digest": "b" * 64, "resources": self.resources, "now": 1001}
        options.update(changes)
        return results.verify_execution_binding(self.case, self.receipt, self.record, **options)

    def test_all_case_bindings_are_verified_without_a_course_or_security_verdict(self):
        for index in range(27):
            self.sample(index)
            outcome = self.verify()
            self.assertTrue(outcome["execution_verified"])
            self.assertNotIn("task_completed", outcome)
            self.assertNotIn("security_verdict", outcome)

    def test_aws_metadata_is_bound_but_not_mistaken_for_guardrail_effectiveness(self):
        self.sample(mode="aws")
        before = deepcopy(self.record)
        self.assertEqual(self.verify()["provider_mode"], "aws")
        self.assertEqual(self.record, before)
        self.assertEqual(self.verify()["provider_mode"], "aws")
        self.record["calls"][0]["provider_request_id"] = "unrelated"
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_changed_identity_build_policy_mode_or_input_is_rejected(self):
        for key, value in (("suite_id", str(uuid4())), ("execution_id", str(uuid4())),
                           ("source_digest", "d" * 64), ("runner_digest", "e" * 64),
                           ("resource_digest", "f" * 64), ("provider_mode", "aws"),
                           ("practice_id", "P03"), ("activity_id", "H03"),
                           ("contract_version", "old"), ("body", {}), ("guardrail", {})):
            self.sample()
            self.record[key] = value
            with self.assertRaises(results.EvidenceError, msg=key):
                self.verify()

    def test_aws_audits_require_both_phases_current_resources_and_unique_requests(self):
        mutations = (
            lambda r: r.pop('policy_audits'),
            lambda r: r['policy_audits'].pop('after'),
            lambda r: r['policy_audits']['before'].update(started_at=999),
            lambda r: r['policy_audits']['after'].update(observed_at=1002),
            lambda r: r['policy_audits']['after'].update(resources={}),
            lambda r: r['policy_audits']['after'].update(scope='registered-resource-state'),
            lambda r: r['policy_audits']['after'].update(
                aws_request_ids=r['policy_audits']['before']['aws_request_ids']),
            lambda r: r['policy_audits']['after']['aws_request_ids'].__setitem__(
                0, r['calls'][0]['provider_request_id']),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.sample(mode='aws')
                mutate(self.record)
                with self.assertRaises(results.EvidenceError):
                    self.verify()

    def test_contract_records_cannot_claim_aws_policy_audits(self):
        self.sample()
        self.record['policy_audits'] = {'before': {}}
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_missing_open_stale_future_and_backward_records_are_rejected(self):
        for key, value in (("closed", False), ("closed_at", None), ("closed_at", 999),
                           ("closed_at", 1002), ("started_at", True), ("calls", None)):
            self.sample()
            self.record[key] = value
            with self.assertRaises(results.EvidenceError, msg=key):
                self.verify()
        self.sample()
        with self.assertRaises(results.EvidenceError):
            self.verify(now=1900)

    def test_pending_missing_or_duplicate_calls_are_rejected(self):
        for mutation in (lambda r: r.update(calls=[]),
                         lambda r: r["calls"].append(deepcopy(r["calls"][0])),
                         lambda r: r["calls"][0].update(state="pending"),
                         lambda r: r["calls"][0].update(dispatched_at=None),
                         lambda r: r["calls"][0].update(observation_id="not-uuid")):
            self.sample()
            mutation(self.record)
            with self.assertRaises(results.EvidenceError):
                self.verify()

    def test_request_digests_and_independent_arguments_must_both_match(self):
        self.sample()
        call = self.record["calls"][0]
        call["request"]["source"] = "INPUT"
        call["request_digest"] = self.receipt["execution"]["calls"][0]["request_digest"] = results.sha(call["request"])
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_numeric_zero_equivalent_but_boolean_and_float_token_limits_are_rejected(self):
        for field, value, permitted in (("temperature", 0, True), ("temperature", False, False),
                                       ("maxTokens", 128.0, False)):
            self.sample(2)
            call = self.record["calls"][0]
            call["request"]["inferenceConfig"][field] = value
            call["request_digest"] = self.receipt["execution"]["calls"][0]["request_digest"] = results.sha(call["request"])
            if permitted:
                self.assertTrue(self.verify()["execution_verified"])
            else:
                with self.assertRaises(results.EvidenceError):
                    self.verify()

    def test_changed_return_or_local_digest_is_rejected(self):
        self.sample()
        self.receipt["execution"]["result"] = {"fixture": "changed"}
        with self.assertRaises(results.EvidenceError):
            self.verify()
        self.sample()
        self.receipt["execution"]["calls"][0]["response_digest"] = "f" * 64
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_resource_namespace_mismatch_is_not_repaired_by_matching_hash(self):
        self.sample(mode="aws")
        self.resources["guardrail_arn"] = "arn:aws:bedrock:eu-west-1:000000000000:guardrail/p04fixture"
        self.record["resource_digest"] = results.sha(self.resources)
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_local_http_status_is_not_coerced_from_float(self):
        self.sample()
        self.receipt["execution"]["calls"][0]["http_status"] = 200.0
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_deny_all_starter_timeout_and_swallowed_error_are_not_verified(self):
        for state in ("rejected", "not_implemented", "timeout", "runtime_error"):
            self.sample()
            self.receipt["execution"]["execution_status"] = state
            with self.assertRaises(results.EvidenceError):
                self.verify()
        self.sample(25)
        self.receipt["execution"].update(execution_status="returned", result={})
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_provider_error_fixture_requires_dispatch_and_cannot_mask_real_aws_failure(self):
        self.sample(25)
        self.record["calls"][0]["dispatched_at"] = None
        with self.assertRaises(results.EvidenceError):
            self.verify()
        self.sample(25, mode="aws")
        self.case["backend"] = "provider"
        self.record["provider_mode"] = "aws"
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_rejected_input_requires_closed_zero_calls_and_an_invalid_server_case(self):
        self.sample(7)
        self.assertTrue(self.verify()["execution_verified"])
        self.receipt["execution"]["calls"] = [{"state": "error"}]
        with self.assertRaises(results.EvidenceError):
            self.verify()
        self.sample()
        self.case["expected"] = "rejected"
        self.receipt["execution"].update(execution_status="rejected", calls=[])
        self.record["calls"] = []
        with self.assertRaises(results.EvidenceError):
            self.verify()

    def test_collector_is_get_only_and_rechecks_unchanged_record(self):
        self.sample()
        requests = []

        def handle(request):
            requests.append(request)
            return httpx.Response(200, json=self.record)

        fetch = collector.ExecutionVerification("http://fixture", "v" * 32,
                                               transport=httpx.MockTransport(handle))
        with patch.object(collector.time, "time", return_value=1001):
            answer = fetch.collect(self.case, self.receipt, suite_id=self.suite, execution_id=self.execution,
                source_digest="a" * 64, runner_digest="b" * 64, resources=self.resources)
        self.assertTrue(answer["binding_result"]["execution_verified"])
        self.assertEqual([r.method for r in requests], ["GET", "GET"])

    def test_collector_refuses_unavailable_redirected_oversized_and_changed_records(self):
        self.sample()
        for fault in ("missing", "redirect", "oversized", "changed"):
            calls = []

            def handle(request):
                calls.append(request)
                if fault == "missing":
                    return httpx.Response(404)
                if fault == "redirect":
                    return httpx.Response(302, headers={"Location": "http://elsewhere"})
                if fault == "oversized":
                    return httpx.Response(200, content=b" " * 131073)
                record = deepcopy(self.record)
                if len(calls) == 2:
                    record["closed_at"] += .1
                return httpx.Response(200, json=record)

            fetch = collector.ExecutionVerification("http://fixture", "v" * 32,
                                                   transport=httpx.MockTransport(handle))
            with patch.object(collector.time, "time", return_value=1001):
                with self.assertRaises(results.EvidenceError):
                    fetch.collect(self.case, self.receipt, suite_id=self.suite, execution_id=self.execution,
                        source_digest="a" * 64, runner_digest="b" * 64, resources=self.resources)
            self.assertEqual(len(calls), 2 if fault == "changed" else 1)


class RealTCPBindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = flow.WorkflowTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_27_real_worker_records_are_independently_refetched_and_verified(self):
        fixture = self.fixture
        fetch = collector.ExecutionVerification(fixture.origin, flow.gateway.VERIFIER)
        for index, case in enumerate(case_module.cases()):
            receipt, record = fixture.run_case(index)
            outcome = fetch.collect(case, receipt, suite_id=fixture.suite,
                execution_id=fixture.rows[index]["execution_id"], source_digest=receipt["source_digest"],
                runner_digest="b" * 64, resources=fixture.resources)
            self.assertTrue(outcome["binding_result"]["execution_verified"], case["case_id"])
            self.assertEqual(outcome["provider_evidence"], record)
        self.assertEqual(len(fixture.backend_calls), 9)


if __name__ == "__main__":
    unittest.main()
