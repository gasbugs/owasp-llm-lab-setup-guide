"""Case checks using real child/TCP/SQLite evidence; provider data is synthetic."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import sys

import httpx

import test_guided_p03_workflow as flow

PATH = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-evidence-verifier/p03_results.py"
spec = importlib.util.spec_from_file_location("p03_results_test", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
collect_spec = importlib.util.spec_from_file_location("p03_verification_test", PATH.with_name("p03_verification.py"))
collector = importlib.util.module_from_spec(collect_spec)
with patch.dict(sys.modules, {"p03_results": module}):
    collect_spec.loader.exec_module(collector)


class ResultsTests(unittest.TestCase):
    stop = flow.WorkflowTests.stop
    run_case = flow.WorkflowTests.run_case

    def setUp(self):
        flow.WorkflowTests.setUp(self)
        self.uri = "s3://p03-fixture/h03/knowledge/current-policy.md"
        self.backend.job_status.return_value["provider_mode"] = "contract"
        self.backend.retrieve.return_value = {
            "ingestion_job_id": self.job, "provider_mode": "contract",
            "results": [{"location": {"type": "S3", "s3Location": {"uri": self.uri}},
                         "content": {"text": "Current synthetic policy"}, "score": 0.7}]}

    def expected(self, result, outcome="ready", **extra):
        return {"suite_id": result["suite_id"], "execution_id": result["execution_id"],
                "current_job_id": self.job, "outcome": outcome, "source_uris": [self.uri],
                "status_response": deepcopy(self.backend.job_status.return_value), **extra}

    def check(self, result, record, outcome="ready", *, expected=None, mode="contract", **extra):
        return module.verify_case(expected or self.expected(result, outcome, **extra), result, record,
                                  source_digest=result["source_digest"], runner_digest="b" * 64,
                                  now=time.time(), provider_mode=mode)

    def test_current_search_and_same_response_are_verified_without_course_grade(self):
        result, record = self.run_case()
        verdict = self.check(result, record)
        self.assertTrue(verdict["case_verified"])
        self.assertEqual(verdict["calls"], 2)
        self.assertEqual(len(verdict["observation_ids"]), 2)
        self.assertNotIn("task_completed", verdict)
        self.assertNotIn("security_verdict", verdict)

    def test_read_only_tcp_requery_matches_the_real_closed_sqlite_record(self):
        result, record = self.run_case()
        verifier = collector.CaseVerification(self.origin, "workflow-verifier")
        collected = verifier.collect(self.expected(result), result, source_digest=result["source_digest"],
                                     runner_digest="b" * 64, provider_mode="contract")
        self.assertEqual(collected["provider_evidence"], record)
        self.assertTrue(collected["case_result"]["case_verified"])
        self.assertEqual(self.ledger.read(result["execution_id"]), record)
        wrong = collector.CaseVerification(self.origin, "workflow-control")
        with self.assertRaises(module.EvidenceError):
            wrong.collect(self.expected(result), result, source_digest=result["source_digest"],
                          runner_digest="b" * 64, provider_mode="contract")

    def test_collection_rejects_missing_redirect_oversize_and_changed_evidence(self):
        result, record = self.run_case()
        responses = [httpx.Response(404), httpx.Response(302, headers={"Location": "http://unused/"}),
                     httpx.Response(200, content=b" " * 131073), httpx.Response(200, json=[])]
        for response in responses:
            requests = []
            def respond(request):
                requests.append(request)
                return response
            verifier = collector.CaseVerification("http://fixture", "fixture-verifier",
                                                   transport=httpx.MockTransport(respond))
            with self.assertRaises(module.EvidenceError):
                verifier.collect(self.expected(result), result, source_digest=result["source_digest"],
                                 runner_digest="b" * 64, provider_mode="contract")
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].method, "GET")
        snapshots = iter([record, {**record, "current_job_id": "changed"}])
        verifier = collector.CaseVerification("http://fixture", "fixture-verifier",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=next(snapshots))))
        with self.assertRaises(module.EvidenceError):
            verifier.collect(self.expected(result), result, source_digest=result["source_digest"],
                             runner_digest="b" * 64, provider_mode="contract")

    def test_all_progress_states_require_one_closed_call(self):
        for status in ("QUEUED", "STARTING", "IN_PROGRESS"):
            self.backend.job_status.return_value["status"] = status
            result, record = self.run_case()
            self.assertEqual(self.check(result, record, "waiting")["calls"], 1)
        self.backend.retrieve.assert_not_called()

    def test_failed_unknown_missing_and_wrong_job_require_actual_rejection(self):
        payloads = [{"ingestion_job_id": self.job, "status": state}
                    for state in ("FAILED", "STOPPING", "STOPPED", "UNKNOWN", None, 0, [])]
        payloads += [{"status": "COMPLETE"}, {"ingestion_job_id": self.job},
                     {"ingestion_job_id": "previous", "status": "COMPLETE"}]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.backend.job_status.return_value = {"provider_mode": "contract", **payload}
                result, record = self.run_case()
                self.assertTrue(self.check(result, record, "rejected")["case_verified"])
        self.backend.retrieve.assert_not_called()

    def test_declared_fixture_service_errors_check_propagation_not_security_pass(self):
        for operation in ("job_status", "retrieve"):
            self.backend.job_status.side_effect = None
            self.backend.retrieve.side_effect = None
            getattr(self.backend, operation).side_effect = RuntimeError("synthetic service failure")
            result, record = self.run_case()
            verdict = self.check(result, record, "provider_error", failed_operation=operation)
            self.assertTrue(verdict["case_verified"])
            self.assertNotIn("security_verdict", verdict)
            with self.assertRaises(module.EvidenceError):
                self.check(result, record, "ready")

    def test_unimplemented_and_no_calls_never_complete_a_case(self):
        self.source.write_text((flow.worker.LAB / "learner.py").read_text())
        result, record = self.run_case()
        with self.assertRaises(module.EvidenceError):
            self.check(result, record)
        self.source.write_text('async def search_current(current_job_id, services):\n    return {"status": "waiting", "result": None}\n')
        result, record = self.run_case()
        with self.assertRaises(module.EvidenceError):
            self.check(result, record, "waiting")

    def test_alternative_implementation_and_comment_change_are_not_hash_answers(self):
        self.source.write_text('''# Another implementation of the same contract.
async def search_current(current_job_id, services):
    state = await services.job_status()
    if state.get("ingestion_job_id") == current_job_id:
        if state.get("status") == "COMPLETE":
            result = await services.retrieve()
            return dict(status="ready", result=result)
        if state.get("status") in ("QUEUED", "STARTING", "IN_PROGRESS"):
            return dict(status="waiting", result=None)
    raise ValueError()
''')
        result, record = self.run_case()
        self.assertTrue(self.check(result, record)["case_verified"])

    def test_changed_return_and_omitted_retrieval_fail_despite_closed_execution(self):
        self.source.write_text(flow.worker.IMPLEMENTATION.replace(
            '"result": await services.retrieve()', '"result": {}'))
        result, record = self.run_case()
        with self.assertRaises(module.EvidenceError):
            self.check(result, record)

    def test_missing_old_foreign_unclosed_and_reordered_evidence_rejected(self):
        result, record = self.run_case()
        mutations = [
            lambda r: r.update(practice_id="P02"), lambda r: r.update(activity_id="H02"),
            lambda r: r.update(contract_version="old"), lambda r: r.update(closed=False),
            lambda r: r.update(current_job_id="previous"), lambda r: r.update(suite_id="other"),
            lambda r: r.update(source_digest="c" * 64), lambda r: r.update(runner_digest="d" * 64),
            lambda r: r.update(calls=[]), lambda r: r["calls"].reverse(),
            lambda r: r.update(started_at=r["started_at"] - 181),
            lambda r: r.update(closed_at=time.time() + 10),
            lambda r: r["calls"][0].update(sequence=True),
            lambda r: r["calls"][0].update(state="pending"),
            lambda r: r["calls"][1].update(observation_id=r["calls"][0]["observation_id"]),
            lambda r: r["calls"][0].update(request_digest="e" * 64),
            lambda r: r["calls"][0].update(finished_at=r["closed_at"] + 1),
            lambda r: r["calls"][0]["response"].update(provider_mode="aws"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                altered = deepcopy(record)
                mutate(altered)
                with self.assertRaises(module.EvidenceError):
                    self.check(result, altered)
        with self.assertRaises(module.EvidenceError):
            self.check(result, {})

    def test_wrong_source_uri_empty_result_and_changed_content_return_fail(self):
        for results in ([], [{"location": {"type": "S3", "s3Location": {"uri": "s3://other/old.md"}},
                             "content": {"text": "old"}}]):
            self.backend.retrieve.return_value["results"] = results
            result, record = self.run_case()
            with self.assertRaises(module.EvidenceError):
                self.check(result, record)

    def aws_shape(self):
        identity = {"ingestion_job_id": self.job, "provider_ingestion_job_id": "JOB1234567",
                    "knowledge_base_id": "KB12345678", "data_source_id": "DS12345678", "provider_mode": "aws"}
        self.backend.job_status.return_value = {**identity, "status": "COMPLETE", "statistics": {"numberOfDocumentsFailed": 0},
                                                "provider_request_id": "status-read"}
        self.backend.retrieve.return_value.update(identity)
        self.backend.retrieve.return_value.update(provider_request_id="retrieve-read", status_observation={
            **self.backend.job_status.return_value, "provider_request_id": "status-recheck"})
        return {key: value for key, value in identity.items() if key not in {"ingestion_job_id", "provider_mode"}}

    def test_malformed_native_result_fields_are_not_trusted(self):
        original = deepcopy(self.backend.retrieve.return_value["results"][0])
        for changes in ({"score": True}, {"score": "0.7"}, {"metadata": []}, {"content": {"text": ""}}):
            self.backend.retrieve.return_value["results"] = [{**original, **changes}]
            result, record = self.run_case()
            self.assertEqual(result["execution"]["execution_status"], "returned")
            with self.assertRaises(module.EvidenceError):
                self.check(result, record)

    def test_aws_shaped_fixture_requires_native_ids_and_recheck(self):
        binding = self.aws_shape()
        result, record = self.run_case()
        expected = self.expected(result, **binding)
        verdict = self.check(result, record, expected=expected, mode="aws")
        self.assertEqual(verdict["provider_request_ids"], ["status-read", "retrieve-read", "status-recheck"])
        for key in binding:
            wrong = {**expected, key: "FOREIGN"}
            with self.assertRaises(module.EvidenceError):
                self.check(result, record, expected=wrong, mode="aws")

    def test_aws_shaped_recheck_failure_or_reused_id_cannot_pass(self):
        for index, change in enumerate(({"status": "IN_PROGRESS"}, {"provider_request_id": "reused"},
                       {"statistics": {"numberOfDocumentsFailed": 1}}, {"knowledge_base_id": "OTHER"},
                       {"statistics": {}}, {"statistics": {"numberOfDocumentsFailed": False}})):
            binding = self.aws_shape()
            self.backend.job_status.return_value["provider_request_id"] = f"status-{index}"
            self.backend.retrieve.return_value["provider_request_id"] = f"retrieval-{index}"
            self.backend.retrieve.return_value["status_observation"]["provider_request_id"] = f"recheck-{index}"
            if "provider_request_id" in change:
                change = {"provider_request_id": f"status-{index}"}
            self.backend.retrieve.return_value["status_observation"].update(change)
            result, record = self.run_case()
            self.assertEqual([call["state"] for call in record["calls"]], ["complete", "complete"])
            self.assertEqual(result["execution"]["execution_status"], "returned")
            with self.assertRaises(module.EvidenceError):
                self.check(result, record, expected=self.expected(result, **binding), mode="aws")


if __name__ == "__main__":
    unittest.main()
