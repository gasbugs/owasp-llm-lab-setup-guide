"""Deployment adapter keeps P03 resources separate and SDK clients lazy."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
import test_guided_p03_run_server as shared
import test_guided_p03_backend as sdk_fixture

for name in ("p03_resource_contract", "p03_preparation", "p03_create_resources", "p03_seed_document", "p03_aws_preparation"):
    shared.flow.gateway.load(name)
gateway = shared.flow.gateway.load("p03_gateway")
sdk_client = gateway.boto3.client


class GatewayTests(unittest.TestCase):
    control = {"Authorization": "Bearer p03-control"}
    verifier = {"Authorization": "Bearer gateway-reader"}

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Path(temp.name) / "gateway.sqlite3"
        self.operation = str(uuid4())
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE resource_state(logical_name TEXT PRIMARY KEY, state_json TEXT NOT NULL)")
        self.sdk = patch.object(gateway.boto3, "client", side_effect=AssertionError("unexpected AWS client"))
        self.client_factory = self.sdk.start()
        self.addCleanup(self.sdk.stop)

    def client(self, mode, provision_token=None):
        client = TestClient(gateway.configured_app(self.database, provider_mode=mode,
                            control_token="p03-control", verifier_token="gateway-reader", region="us-east-1",
                            provision_token=provision_token))
        self.addCleanup(client.close)
        return client

    def mapping(self):
        return {"suite_id": str(uuid4()), "executions": [
            {"case_id": case["case_id"], "execution_id": str(uuid4())} for case in gateway.load_cases()]}

    def state(self, name, value):
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT OR REPLACE INTO resource_state VALUES(?,?)", (name, json.dumps(value)))

    def snapshot(self):
        return {"provider_mode": "aws", "binding": {
            "current_job_id": "p03-" + self.operation.replace("-", ""), "provider_ingestion_job_id": "JOB1234567",
            "knowledge_base_id": "KB12345678", "data_source_id": "DS12345678",
            "source_uri_prefix": "s3://owasp-guided-p03-000000000000-source/h03/knowledge/", "region": "us-east-1"},
            "source_uris": ["s3://owasp-guided-p03-000000000000-source/h03/knowledge/current-policy.md"]}

    def prepared(self, snapshot=None):
        store = gateway.PreparationStore(self.database)
        store.begin(self.operation, "000000000000")
        store.publish(self.operation, snapshot or self.snapshot())

    def register(self, client, mapping, ordinal=0):
        return client.post("/executions", headers=self.control, json={
            "suite_id": mapping["suite_id"], "execution_id": mapping["executions"][ordinal]["execution_id"],
            "source_digest": "a" * 64, "runner_digest": "b" * 64})

    def test_contract_full_call_lifecycle_and_reader_are_aws_free(self):
        client, mapping = self.client("contract"), self.mapping()
        self.assertEqual(client.post("/suites", headers=self.control, json=mapping).status_code, 200)
        grant = self.register(client, mapping).json()
        for operation in ("job_status", "retrieve"):
            response = client.post("/invoke", headers={"Authorization": "Bearer " + grant["capability"]},
                json={"suite_id": mapping["suite_id"], "execution_id": grant["execution_id"],
                      "operation": operation, "payload": {}})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["response"]["provider_mode"], "contract")
        self.assertEqual(client.post("/executions/" + grant["execution_id"] + "/close", headers=self.control, json={}).status_code, 200)
        record = client.get("/executions/" + grant["execution_id"], headers=self.verifier).json()
        self.assertEqual(len(record["calls"]), 2)
        self.assertIsNotNone(record["closed_at"])
        self.assertEqual(client.get("/suites/" + mapping["suite_id"] + "/resources", headers=self.verifier).status_code, 200)
        self.client_factory.assert_not_called()

    def test_missing_p03_never_uses_h03_p02_or_p11(self):
        for name in ("h03", "h02", "p02", "h11", "p11"):
            self.state(name, self.snapshot())
        client, mapping = self.client("aws"), self.mapping()
        self.assertEqual(client.post("/suites", headers=self.control, json=mapping).status_code, 409)
        record = client.get("/suites/" + mapping["suite_id"], headers=self.verifier).json()
        self.assertEqual(record["state"], "error")
        self.assertEqual(self.register(client, mapping).status_code, 409)
        self.client_factory.assert_not_called()

    def test_aws_registration_is_read_only_and_contract_cases_use_no_sdk(self):
        self.prepared()
        client, mapping = self.client("aws"), self.mapping()
        self.assertEqual(client.post("/suites", headers=self.control, json=mapping).status_code, 200)
        grant = self.register(client, mapping, ordinal=1).json()
        result = client.post("/invoke", headers={"Authorization": "Bearer " + grant["capability"]}, json={
            "suite_id": mapping["suite_id"], "execution_id": grant["execution_id"], "operation": "job_status", "payload": {}})
        self.assertEqual(result.json()["response"]["provider_mode"], "contract")
        with sqlite3.connect(self.database) as db:
            self.assertEqual(json.loads(db.execute("SELECT state_json FROM resource_state WHERE logical_name='p03'").fetchone()[0]), self.snapshot())
        self.client_factory.assert_not_called()

    def test_wrong_mode_region_or_malformed_resource_fails_closed(self):
        client = self.client("aws")
        wrong_region = self.snapshot()
        wrong_region["binding"]["region"] = "us-west-2"
        for state in ({}, {"provider_mode": "contract", "binding": None, "source_uris": [gateway.CONTRACT_URI]}, wrong_region):
            with self.subTest(state=state):
                self.state("p03", state)
                self.assertEqual(client.post("/suites", headers=self.control, json=self.mapping()).status_code, 409)
        self.client_factory.assert_not_called()

    def test_changed_resource_rejected_by_reader(self):
        self.prepared()
        client, mapping = self.client("aws"), self.mapping()
        self.assertEqual(client.post("/suites", headers=self.control, json=mapping).status_code, 200)
        changed = self.snapshot()
        changed["binding"]["provider_ingestion_job_id"] = "JOB7654321"
        self.state("p03", changed)
        self.assertEqual(client.get("/suites/" + mapping["suite_id"] + "/resources", headers=self.verifier).status_code, 409)
        self.client_factory.assert_not_called()

    def test_configuration_requires_explicit_mode(self):
        with self.assertRaises(ValueError):
            self.client("automatic")
        with self.assertRaises(ValueError):
            gateway.configured_app(self.database, provider_mode="aws", control_token="p03-control",
                                   verifier_token="gateway-reader", region="us-west-2")

    def test_old_p03_row_without_preparation_journal_is_not_ready(self):
        self.state("p03", self.snapshot())
        client = self.client("aws")
        self.assertEqual(client.post("/suites", headers=self.control, json=self.mapping()).status_code, 409)

    def test_new_failed_preparation_invalidates_old_ready_binding(self):
        self.prepared()
        store = gateway.PreparationStore(self.database)
        operation = str(uuid4())
        store.begin(operation, "000000000000")
        store.fail(operation)
        client = self.client("aws")
        self.assertEqual(client.post("/suites", headers=self.control, json=self.mapping()).status_code, 409)

    def test_contract_preparation_never_calls_aws(self):
        client = self.client("contract", "preparer")
        response = client.post("/resources/prepare", headers={"Authorization": "Bearer preparer"},
                               json={"operation_id": self.operation})
        self.assertEqual(response.status_code, 409)
        self.client_factory.assert_not_called()

    def test_preparation_discovers_account_only_after_authentication(self):
        client = self.client("aws", "preparer")
        self.assertEqual(client.post("/resources/prepare", headers=self.control,
            json={"operation_id": self.operation}).status_code, 401)
        self.client_factory.assert_not_called()
        self.client_factory.side_effect = None
        self.client_factory.return_value = Mock()
        self.client_factory.return_value.get_caller_identity.return_value = {
            "Account": "000000000000", "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "sts-id"}}
        with patch.object(gateway, "prepare_aws", return_value={"state": "ready"}) as prepare:
            response = client.post("/resources/prepare", headers={"Authorization": "Bearer preparer"},
                                   json={"operation_id": self.operation})
        self.assertEqual(response.status_code, 200)
        prepare.assert_called_once_with(self.database, self.operation, "000000000000")

    def test_native_adapter_uses_bound_sdk_ids_and_single_attempt_clients(self):
        with patch.object(sdk_fixture.boto3, "client", sdk_client):
            sdk_fixture.BackendTests.setUp(self)
        snapshot = self.snapshot()
        self.binding = replace(self.binding, source_uri_prefix=snapshot["binding"]["source_uri_prefix"])
        self.result["retrievalResults"][0]["location"]["s3Location"]["uri"] = self.binding.source_uri_prefix + "current-policy.md"
        self.prepared(snapshot)
        sdk_fixture.BackendTests.queue_status(self)
        recheck = deepcopy(self.status)
        recheck["ResponseMetadata"]["RequestId"] = "status-recheck"
        sdk_fixture.BackendTests.queue_status(self, recheck)
        sdk_fixture.BackendTests.queue_retrieval(self)
        self.client_factory.side_effect = lambda name, **kwargs: {
            "bedrock-agent": self.agent, "bedrock-agent-runtime": self.runtime}[name]
        client, mapping = self.client("aws"), self.mapping()
        self.assertEqual(client.post("/suites", headers=self.control, json=mapping).status_code, 200)
        grant = self.register(client, mapping).json()
        self.client_factory.assert_not_called()
        for operation in ("job_status", "retrieve"):
            result = client.post("/invoke", headers={"Authorization": "Bearer " + grant["capability"]}, json={
                "suite_id": mapping["suite_id"], "execution_id": grant["execution_id"], "operation": operation, "payload": {}})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()["response"]["provider_mode"], "aws")
            self.assertEqual(result.json()["response"]["provider_ingestion_job_id"], "JOB1234567")
        self.assertEqual(self.client_factory.call_count, 4)
        for call in self.client_factory.call_args_list:
            self.assertEqual(call.kwargs["region_name"], "us-east-1")
            config = call.kwargs["config"]
            self.assertEqual(config.retries["total_max_attempts"], 1)
            self.assertEqual((config.connect_timeout, config.read_timeout), (5, 20))


if __name__ == "__main__":
    unittest.main()
