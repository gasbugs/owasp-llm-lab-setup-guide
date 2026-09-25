"""Actual child -> TCP API -> SQLite/SDK-double -> independent comparison.

This is a local contract integration, not an AWS or deployed Compose E2E.
"""
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import socket
import shutil
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import Mock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import uvicorn

from test_guided_p02_api import api, ledger_module, provider_module
from test_guided_p02_execution import IMPLEMENTATION, module as execution_module
from test_guided_p02_run_server import module as runner_module, case_module

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


previous = sys.modules.get("execution")
sys.modules["execution"] = execution_module
try:
    workflow_module = load("p02_workflow", ROOT / "guided-labs/h02-document-ingestion/workflow.py")
finally:
    if previous is None:
        del sys.modules["execution"]
    else:
        sys.modules["execution"] = previous
grading = load("p02_results", ROOT / "guided-evidence-verifier/p02_results.py")
previous = sys.modules.get("p02_results")
sys.modules["p02_results"] = grading
try:
    verification_module = load("p02_verification", ROOT / "guided-evidence-verifier/p02_verification.py")
finally:
    if previous is None:
        del sys.modules["p02_results"]
    else:
        sys.modules["p02_results"] = previous


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "learner.py"
        self.source.write_text(IMPLEMENTATION)
        self.store = ledger_module.DocumentLedger(Path(self.temp.name) / "gateway.sqlite3")
        self.s3, self.runtime, self.objects = Mock(), Mock(), {}

        def put(**kwargs):
            self.objects[kwargs["Key"]] = kwargs["Body"]
            return {"ResponseMetadata": {"RequestId": "put-" + str(uuid4())}}

        def get(**kwargs):
            return {"Body": io.BytesIO(self.objects[kwargs["Key"]]), "ResponseMetadata": {"RequestId": "get-" + str(uuid4())}}

        def embed(**kwargs):
            return {"body": io.BytesIO(json.dumps({"embedding": [1.0] + [0.0] * 1023, "inputTextTokenCount": 6}).encode()),
                    "ResponseMetadata": {"RequestId": "embed-" + str(uuid4())}}

        self.s3.put_object.side_effect, self.s3.get_object.side_effect = put, get
        self.runtime.invoke_model.side_effect = embed
        provider = provider_module.DocumentProvider(self.store, self.s3, self.runtime, "fixture-bucket")
        def resource_fixture():
            return {"connection_verified": True, "provider_mode": "aws", "observed_at": time.time(),
                    "resource_request_ids": [str(uuid4()) for _ in range(4)],
                    "binding": {"account_id": "000000000000", "region": "us-east-1", "template_digest": "c" * 64,
                        "source_bucket": "fixture-bucket", "source_prefix": "h02/knowledge/", "vector_bucket": "fixture-vectors",
                        "index_arn": "fixture-index", "knowledge_base_id": "fixture-kb", "data_source_id": "fixture-ds",
                        "embedding_model_id": "amazon.titan-embed-text-v2:0", "dimensions": 1024}}
        app = FastAPI()
        app.mount("/v1/p02", api.create_app(self.store, lambda: provider, control_token="control-fixture", verifier_token="verifier-fixture",
                                           resource_reader=resource_fixture))
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.origin = f"http://127.0.0.1:{self.socket.getsockname()[1]}"
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 5
        while not self.server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.server.started)
        self.workflow = workflow_module.Workflow(self.origin, "control-fixture")
        self.expected = {"suite_id": str(uuid4()), "execution_id": str(uuid4()), "valid": True,
                         "body": {"title": "연결 안내", "body": "이 문서는 합성 실습 원문입니다."}}

    def stop_server(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.socket.close()

    def run_case(self):
        return self.workflow.run_case(self.source, self.expected["body"], suite_id=self.expected["suite_id"],
                                       execution_id=self.expected["execution_id"], runner_digest="b" * 64)

    def evidence(self, source=True):
        headers = {"Authorization": "Bearer verifier-fixture"}
        url = self.origin + "/v1/p02/executions/" + self.expected["execution_id"]
        with httpx.Client(timeout=5, trust_env=False) as client:
            ledger = client.get(url, headers=headers)
            self.assertEqual(ledger.status_code, 200)
            body = None
            if source:
                response = client.get(url + "/source", headers=headers)
                self.assertEqual(response.status_code, 200)
                body = response.json()
        return ledger.json(), body

    def verify(self, result, ledger, source):
        return grading.verify_case(self.expected, result, ledger, source,
                                   source_digest=result["source_digest"], runner_digest="b" * 64, bucket="fixture-bucket")

    def test_actual_function_tcp_lifecycle_and_independent_comparison(self):
        result = self.run_case()
        ledger, source = self.evidence()
        self.assertEqual(self.verify(result, ledger, source)["calls"], 2)
        self.assertEqual(self.s3.put_object.call_count, 1)
        self.assertEqual(self.runtime.invoke_model.call_count, 1)
        self.assertNotIn("control-fixture", json.dumps(result))
        self.assertNotIn("capability", json.dumps(result))
        self.assertNotIn("task_completed", result)

    def test_rejected_input_has_explicit_closed_zero_call_evidence(self):
        self.expected["body"]["object_key"] = "client-key"
        self.expected["valid"] = False
        result = self.run_case()
        ledger, source = self.evidence(source=False)
        self.assertEqual(self.verify(result, ledger, source)["calls"], 0)
        self.s3.put_object.assert_not_called()
        self.runtime.invoke_model.assert_not_called()

    def test_starter_is_finished_execution_but_not_verified_case(self):
        self.source.write_text(ROOT.joinpath("guided-labs/h02-document-ingestion/learner.py").read_text())
        result = self.run_case()
        ledger, source = self.evidence(source=False)
        self.assertEqual(result["lifecycle_status"], "finished")
        self.assertTrue(ledger["closed"])
        self.assertEqual(result["execution"]["execution_status"], "not_implemented")
        with self.assertRaises(grading.EvidenceError):
            self.verify(result, ledger, source)

    def test_duplicate_execution_does_not_mutate_existing_closed_record(self):
        self.run_case()
        before, _ = self.evidence()
        duplicate = self.run_case()
        after, _ = self.evidence()
        self.assertEqual(before, after)
        self.assertEqual(duplicate["lifecycle_status"], "error")
        self.assertIsNone(duplicate["execution"])
        self.assertEqual(self.s3.put_object.call_count, 1)

    def test_failure_after_storage_keeps_effect_and_fails_verification(self):
        self.runtime.invoke_model.side_effect = TimeoutError("private detail")
        result = self.run_case()
        ledger, source = self.evidence()
        self.assertEqual(result["execution"]["execution_status"], "service_error")
        self.assertEqual([c["state"] for c in ledger["calls"]], ["complete", "error"])
        self.assertEqual(len(self.objects), 1)
        with self.assertRaises(grading.EvidenceError):
            self.verify(result, ledger, source)

    def test_mutated_provider_binding_is_not_accepted(self):
        result = self.run_case()
        ledger, source = self.evidence()
        mutations = [
            lambda r, l, s: l.update(closed=False),
            lambda r, l, s: l.update(suite_id=str(uuid4())),
            lambda r, l, s: l.update(contract_version="old"),
            lambda r, l, s: l.update(source_digest="d" * 64),
            lambda r, l, s: l.update(runner_digest="d" * 64),
            lambda r, l, s: l["calls"][0].update(state="pending"),
            lambda r, l, s: l["calls"][0].update(sequence=True),
            lambda r, l, s: l["calls"][0].update(request_digest="d" * 64),
            lambda r, l, s: l["calls"][0].update(finished_at=l["closed_at"] + 1),
            lambda r, l, s: l["calls"][1].update(provider_request_id=l["calls"][0]["provider_request_id"]),
            lambda r, l, s: s.update(source_digest="d" * 64),
            lambda r, l, s: s.update(source_bytes=True),
            lambda r, l, s: r["execution"].update(calls=[]),
            lambda r, l, s: r["execution"]["result"].update(source={}),
            lambda r, l, s: r["closure"].update(closed_at=True),
        ]
        for mutate in mutations:
            r, l, s = deepcopy(result), deepcopy(ledger), deepcopy(source)
            mutate(r, l, s)
            with self.assertRaises(grading.EvidenceError):
                self.verify(r, l, s)

    def test_source_changed_remotely_after_execution_is_rejected(self):
        result = self.run_case()
        self.objects[f"h02/knowledge/{self.expected['execution_id']}.md"] = b"changed"
        ledger, source = self.evidence()
        with self.assertRaises(grading.EvidenceError):
            self.verify(result, ledger, source)

    def test_whole_server_owned_suite_executes_and_requeries_all_22_cases(self):
        for name in runner_module.RUNNER_FILES:
            shutil.copyfile(ROOT / "guided-labs/h02-document-ingestion" / name, self.source.parent / name)
        app = runner_module.create_app(workflow=self.workflow, tokens={"control": "runner-control", "verifier": "runner-verifier"},
                                       database=self.source.parent / "runs.sqlite3", source_root=self.source.parent)
        with TestClient(app) as client:
            response = client.post("/v1/run", headers={"Authorization": "Bearer runner-control"},
                                   json={"suite_id": self.expected["suite_id"]})
            self.assertEqual(response.status_code, 200)
            root = response.json()
            self.assertEqual(root["run_state"], "finished")
            self.assertEqual(root["build"], root["final_build"])
            verified = []
            for case, row in zip(case_module.cases(), root["cases"]):
                self.expected = {**case, "suite_id": root["suite_id"], "execution_id": row["execution_id"]}
                ledger, source = self.evidence(source=case["valid"])
                verified.append(grading.verify_case(self.expected, row["execution"], ledger, source,
                                 source_digest=root["build"]["source_digest"], runner_digest=root["build"]["runner_digest"], bucket="fixture-bucket"))
            self.assertEqual(len(verified), 22)
            self.assertEqual(sum(result["calls"] for result in verified), 8)
            self.assertEqual(self.s3.put_object.call_count, 4)
            self.assertEqual(self.runtime.invoke_model.call_count, 4)
            saved = client.get("/v1/receipts/" + root["suite_id"], headers={"Authorization": "Bearer runner-verifier"}).json()
            self.assertEqual(root, saved)
            mutations = {}
            def transport(request):
                if request.url.host == "runner":
                    response = client.get(request.url.path, headers=dict(request.headers))
                else:
                    response = httpx.get(str(request.url), headers=dict(request.headers), trust_env=False)
                payload = response.json()
                if request.url.path in mutations:
                    mutations[request.url.path](payload)
                return httpx.Response(response.status_code, json=payload)
            verifier = verification_module.Verification(self.source.parent, "http://runner", self.origin,
                                                        "runner-verifier", "verifier-fixture")
            with httpx.Client(transport=httpx.MockTransport(transport)) as reader:
                full = verifier.collect(root["suite_id"], reader)
                self.assertTrue(full["case_contract_verified"])
                self.assertEqual(len(full["cases"]), 22)
                invalid_root_mutations = [lambda value: value.update(run_state="running"),
                                          lambda value: value["cases"].pop(),
                                          lambda value: value.update(suite_id=str(uuid4())),
                                          lambda value: value["build"].update(runner_digest="d" * 64),
                                          lambda value: value.update(finished_at=time.time() - 601)]
                for mutation in invalid_root_mutations:
                    mutations["/v1/receipts/" + root["suite_id"]] = mutation
                    with self.assertRaises(grading.EvidenceError):
                        verifier.collect(root["suite_id"], reader)
                mutations.clear()
                mutations["/v1/p02/resources"] = lambda value: value.update(connection_verified=False)
                with self.assertRaises(grading.EvidenceError):
                    verifier.collect(root["suite_id"], reader)


if __name__ == "__main__":
    unittest.main(verbosity=2)
