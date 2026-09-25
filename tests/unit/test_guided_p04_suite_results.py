"""Whole-suite synthetic evidence tests; these do not call AWS."""
from copy import deepcopy
import sys
import unittest
import time
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx

import test_guided_p04_results as binding
import test_guided_p04_product as product_test
import test_guided_p04_run_server as runner_test

with patch.dict(sys.modules, {"p04_results": binding.results, "p04_product": product_test.product}):
    suite_module = binding.load("p04_suite_results")


class SuiteTests(unittest.TestCase):
    def setUp(self, provider_mode="contract"):
        fixture = binding.BindingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.contract = suite_module.SuiteContract(binding.flow.worker.LAB)
        self.suite = str(uuid4())
        self.rows, self.records = [], []
        for index, case in enumerate(self.contract.cases):
            fixture.sample(index, mode=provider_mode)
            receipt, record = deepcopy(fixture.receipt), deepcopy(fixture.record)
            for value in (receipt, record):
                value.update(suite_id=self.suite, runner_digest=self.contract.runner_digest)
            if case["backend"] == "provider":
                response = product_test.response_for(case)
                if provider_mode == "aws":
                    response['ResponseMetadata'] = {'HTTPStatusCode': 200,
                        'RequestId': record['calls'][0]['provider_request_id']}
                elif case["body"]["operation"] == "converse":
                    mapping = response["trace"]["guardrail"]["outputAssessments"]
                    mapping["p04contract"] = mapping.pop("p04fixture")
                record["calls"][0]["response"] = deepcopy(response)
                receipt["execution"]["result"] = response
                receipt["execution"]["calls"][0]["response_digest"] = binding.results.sha(response)
            self.rows.append({"case_id": case["case_id"], "execution_id": fixture.execution, "execution": receipt})
            self.records.append(record)
        self.resources = deepcopy(fixture.resources)
        self.build = {"source_digest": "a" * 64, "runner_files": self.contract.files,
                      "runner_digest": self.contract.runner_digest, "contract_digest": self.contract.contract_digest}
        identity = {"practice_id": "P04", "activity_id": "H04", "contract_version": "p04-guardrail-v1",
                    "suite_id": self.suite}
        self.root = {**identity, "started_at": 999, "finished_at": 1001, "run_state": "finished",
                     "build": deepcopy(self.build), "final_build": deepcopy(self.build), "cases": self.rows}
        self.registration = {**identity, "started_at": 999, "prepared_at": 1000, "state": "prepared",
            "contract_digest": self.contract.contract_digest, "resources": deepcopy(self.resources),
            "cases": [{key: row[key] for key in ("case_id", "execution_id")} for row in self.rows]}

    def verify(self, **overrides):
        args = dict(suite_id=self.suite, root=self.root, registration=self.registration,
                    build=self.build, records=self.records, resources=self.resources, now=1002)
        args.update(overrides)
        return self.contract.verify(**args)

    def test_all_27_requirements_include_four_product_effects_and_no_course_verdict(self):
        result = self.verify()
        self.assertTrue(result["suite_contract_verified"])
        self.assertEqual(result["provider_mode"], "contract")
        self.assertEqual(len(result["cases"]), 27)
        self.assertEqual(sum(row["product"] is not None for row in result["cases"]), 4)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_missing_extra_reordered_and_duplicate_cases_are_rejected(self):
        original = deepcopy(self.rows)
        for rows in (original[:-1], original + [original[0]], list(reversed(original)),
                     original[:-1] + [original[0]]):
            with self.subTest(rows=len(rows)), self.assertRaises(binding.results.EvidenceError):
                self.verify(root={**self.root, "cases": rows})

    def test_case_mapping_cannot_borrow_another_execution(self):
        self.registration["cases"][0]["execution_id"] = str(uuid4())
        with self.assertRaises(binding.results.EvidenceError):
            self.verify()

    def test_changed_current_final_or_immutable_build_is_rejected(self):
        for location in ("current", "final", "runner"):
            with self.subTest(location=location):
                current, root = deepcopy(self.build), deepcopy(self.root)
                if location == "current":
                    current["source_digest"] = "b" * 64
                elif location == "final":
                    root["final_build"]["source_digest"] = "b" * 64
                else:
                    current["runner_files"]["execution.py"] = "b" * 64
                    root["build"] = root["final_build"] = deepcopy(current)
                with self.assertRaises(binding.results.EvidenceError):
                    self.verify(build=current, root=root)

    def test_source_hash_is_binding_not_an_answer_hash(self):
        self.build["source_digest"] = "d" * 64
        self.root["build"] = self.root["final_build"] = deepcopy(self.build)
        for row, record in zip(self.rows, self.records):
            record["source_digest"] = row["execution"]["source_digest"] = "d" * 64
            row["execution"]["execution"]["source_digest"] = "d" * 64
        self.assertTrue(self.verify()["suite_contract_verified"])

    def test_partial_stale_future_long_running_and_bad_preparation_fail(self):
        for key, value in (("run_state", "running"), ("finished_at", None),
                           ("started_at", 800), ("finished_at", 1003)):
            with self.subTest(key=key), self.assertRaises(binding.results.EvidenceError):
                self.verify(root={**self.root, key: value})
        with self.assertRaises(binding.results.EvidenceError):
            self.verify(now=1900)
        with self.assertRaises(binding.results.EvidenceError):
            self.verify(registration={**self.registration, "prepared_at": 1001})

    def test_changed_resource_and_contract_fail(self):
        with self.assertRaises(binding.results.EvidenceError):
            self.verify(resources={**self.resources, "policy_digest": "d" * 64})
        with self.assertRaises(binding.results.EvidenceError):
            self.verify(registration={**self.registration, "contract_digest": "d" * 64})

    def test_duplicate_observation_and_unfinished_case_fail(self):
        records = deepcopy(self.records)
        records[1]["calls"][0]["observation_id"] = records[0]["calls"][0]["observation_id"]
        with self.assertRaises(binding.results.EvidenceError):
            self.verify(records=records)
        self.rows[-1]["execution"] = None
        with self.assertRaises(binding.results.EvidenceError):
            self.verify()

    def test_matching_raw_response_without_anonymization_does_not_pass(self):
        response = self.records[1]["calls"][0]["response"]
        response["outputs"] = [{"text": self.contract.cases[1]["body"]["text"]}]
        worker = self.rows[1]["execution"]["execution"]
        worker["result"] = deepcopy(response)
        worker["calls"][0]["response_digest"] = binding.results.sha(response)
        with self.assertRaises(binding.results.EvidenceError):
            self.verify()

    def test_starter_cannot_pass_just_because_the_runner_finished(self):
        self.rows[0]["execution"]["execution"].update(execution_status="not_implemented", calls=[])
        with self.assertRaises(binding.results.EvidenceError):
            self.verify()


class RealSuiteTests(unittest.TestCase):
    def setUp(self):
        self.fixture = runner_test.RunnerTCPTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def grade_current(self, root):
        with patch.dict(sys.modules, {"p04_results": binding.results, "p04_suite_results": suite_module}):
            collection = binding.load("p04_suite_verification")
        api = binding.load("p04_grading_api")
        fixture = self.fixture
        requests = []
        with httpx.Client(trust_env=False) as gateway_client:
            def forward(request):
                requests.append(request)
                self.assertEqual(request.method, "GET")
                if request.url.host == "runner":
                    response = fixture.client.get(request.url.path, headers=dict(request.headers))
                else:
                    response = gateway_client.get(fixture.fixture.origin + request.url.path,
                                                  headers=dict(request.headers))
                return httpx.Response(response.status_code, content=response.content)
            verification = collection.SuiteVerification(fixture.root, "http://runner", "http://gateway",
                fixture.tokens["verifier"], fixture.tokens["verifier"], transport=httpx.MockTransport(forward))
            with TestClient(api.create_app(verification, control_token="grading-" * 8)) as client:
                response = client.post("/v1/verify/p04", json={"suite_id": root["suite_id"]},
                    headers={"Authorization": "Bearer " + "grading-" * 8})
                self.assertEqual(response.status_code, 200)
        return response.json(), requests

    def test_actual_children_and_tcp_records_feed_whole_suite_validation(self):
        fixture = self.fixture
        original = binding.flow.gateway.Invocation

        def invocation(ledger, backend, resource_digest):
            def native_shaped(operation, arguments):
                raw = backend(operation, arguments)
                for case in binding.case_module.cases()[:4]:
                    if operation == case["body"]["operation"] and raw["text"] == case["body"]["text"]:
                        response = product_test.response_for(case)
                        if operation == "converse":
                            mapping = response["trace"]["guardrail"]["outputAssessments"]
                            mapping["p04contract"] = mapping.pop("p04fixture")
                        return response
                return raw
            return original(ledger, native_shaped, resource_digest)

        with patch.object(binding.flow.gateway, "Invocation", side_effect=invocation):
            root = fixture.execute_suite()
        records = [fixture.fixture.ledger.read(row["execution_id"]) for row in root["cases"]]
        contract = suite_module.SuiteContract(fixture.root)
        result = contract.verify(root["suite_id"], root, fixture.fixture.store.read(root["suite_id"]),
                                 root["build"], records, fixture.fixture.resources, now=time.time())
        self.assertTrue(result["suite_contract_verified"])
        self.assertEqual(len(result["cases"]), 27)
        self.assertEqual(result["provider_mode"], "contract")
        self.assertEqual(len(fixture.fixture.backend_calls), 9)
        graded, requests = self.grade_current(root)
        self.assertTrue(graded["task_completed"])
        self.assertEqual(graded["security_verdict"], "PASS")
        self.assertEqual(graded["provider_mode"], "contract")
        self.assertEqual(graded["root"], root)
        self.assertEqual(len(requests), 62)
        self.assertEqual(len(fixture.fixture.backend_calls), 9)

    def test_real_starter_27_closed_attempts_are_not_whole_suite_success(self):
        fixture = self.fixture
        fixture.fixture.source.write_text((binding.flow.worker.LAB / "learner.py").read_text())
        root = fixture.execute_suite()
        records = [fixture.fixture.ledger.read(row["execution_id"]) for row in root["cases"]]
        with self.assertRaises(binding.results.EvidenceError):
            suite_module.SuiteContract(fixture.root).verify(root["suite_id"], root,
                fixture.fixture.store.read(root["suite_id"]), root["build"], records,
                fixture.fixture.resources, now=time.time())
        self.assertEqual(fixture.fixture.backend_calls, [])
        graded, _ = self.grade_current(root)
        self.assertFalse(graded["task_completed"])
        self.assertEqual(graded["security_verdict"], "ERR")
        self.assertEqual(fixture.fixture.backend_calls, [])


if __name__ == "__main__":
    unittest.main()
