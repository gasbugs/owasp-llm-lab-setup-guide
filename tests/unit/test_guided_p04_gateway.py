"""P04 native/fixture selection; SDK clients are never created by contract cases."""
from pathlib import Path
import sys
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
import botocore.session
from botocore.stub import Stubber
from botocore.validate import validate_parameters

import test_guided_p04_api as shared
import test_guided_p04_product as product_test

sys.path.insert(0, str(shared.GATEWAY))
try:
    import p04_gateway as gateway
    import p04_backend as backend_module
finally:
    sys.path.remove(str(shared.GATEWAY))


class GatewayTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "gateway.sqlite3"
        self.snapshot = {"provider_mode": "aws", "guardrail": {
            "guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"},
            "guardrail_arn": "arn:aws:bedrock:us-east-1:000000000000:guardrail/p04fixture", "policy_digest": "a" * 64}
        self.sdk_patch = patch.object(backend_module.boto3, "client", side_effect=AssertionError("unexpected AWS"))
        self.sdk = self.sdk_patch.start()
        self.addCleanup(self.sdk_patch.stop)

    def client(self, mode="contract", reader=None, auditor=None):
        client = TestClient(gateway.configured_app(self.path, provider_mode=mode, region="us-east-1",
            control_token=shared.CONTROL, verifier_token=shared.VERIFIER, prepared_resources=reader,
            policy_auditor=auditor))
        self.addCleanup(client.close)
        return client

    def prepare(self, client):
        suite = str(uuid4())
        rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in gateway.load_cases()]
        response = client.post("/suites", json={"suite_id": suite, "cases": rows}, headers=shared.headers(shared.CONTROL))
        self.assertEqual(response.status_code, 200, response.text)
        return suite, rows

    def execute(self, client, suite, rows, index):
        response = client.post("/executions", headers=shared.headers(shared.CONTROL), json={
            "suite_id": suite, "execution_id": rows[index]["execution_id"],
            "source_digest": "a" * 64, "runner_digest": "b" * 64})
        self.assertEqual(response.status_code, 200)
        grant = response.json()
        result = client.post("/invoke", headers=shared.headers(grant["capability"]), json={
            "suite_id": suite, "execution_id": grant["execution_id"], "operation": grant["body"]["operation"],
            "payload": shared.expected_arguments(grant["body"], grant["guardrail"])})
        closed = client.post("/executions/" + grant["execution_id"] + "/close", json={}, headers=shared.headers(shared.CONTROL))
        self.assertEqual(closed.status_code, 200)
        record = client.get("/executions/" + grant["execution_id"], headers=shared.headers(shared.VERIFIER)).json()
        return result, record

    def test_four_contract_product_responses_have_native_shapes_but_no_native_ids(self):
        client = self.client()
        self.assertEqual(client.get("/readyz").status_code, 200)
        suite, rows = self.prepare(client)
        sdk = botocore.session.get_session().get_service_model("bedrock-runtime")
        for index, case in enumerate(gateway.load_cases()[:4]):
            result, record = self.execute(client, suite, rows, index)
            self.assertEqual(result.status_code, 200)
            response = result.json()["response"]
            operation = "ApplyGuardrail" if index < 2 else "Converse"
            validate_parameters(response, sdk.operation_model(operation).output_shape)
            product_test.product.verify_product_response(case, response, record["guardrail"])
            self.assertEqual(record["provider_mode"], "contract")
            self.assertIsNone(record["calls"][0]["provider_request_id"])
            self.assertNotIn("ResponseMetadata", response)
        self.sdk.assert_not_called()

    def test_aws_unprepared_and_wrong_mode_never_fall_back(self):
        for reader in (None, lambda: {**self.snapshot, "provider_mode": "contract"}):
            client = self.client("aws", reader)
            suite = str(uuid4())
            rows = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in gateway.load_cases()]
            response = client.post("/suites", json={"suite_id": suite, "cases": rows}, headers=shared.headers(shared.CONTROL))
            self.assertEqual(response.status_code, 409)
            record = client.get("/suites/" + suite, headers=shared.headers(shared.VERIFIER)).json()
            self.assertEqual(record["state"], "error")
        self.sdk.assert_not_called()

    def test_contract_boundary_and_error_cases_remain_contract_in_aws_mode(self):
        client = self.client("aws", lambda: self.snapshot)
        suite, rows = self.prepare(client)
        for index in (4, 5, 6, 25, 26):
            result, record = self.execute(client, suite, rows, index)
            self.assertEqual(result.status_code, 502 if index >= 25 else 200)
            self.assertEqual(record["provider_mode"], "contract")
            self.assertIsNone(record["calls"][0]["provider_request_id"])
        self.sdk.assert_not_called()

    def test_changed_resource_after_prepare_is_rejected_before_sdk(self):
        client = self.client("aws", lambda: self.snapshot)
        suite, rows = self.prepare(client)
        self.snapshot["policy_digest"] = "d" * 64
        result = client.post("/executions", headers=shared.headers(shared.CONTROL), json={
            "suite_id": suite, "execution_id": rows[0]["execution_id"], "source_digest": "a" * 64, "runner_digest": "b" * 64})
        self.assertEqual(result.status_code, 409)
        self.sdk.assert_not_called()

    def test_native_four_calls_use_exact_registered_parameters_and_native_ids(self):
        session = botocore.session.get_session()
        native = session.create_client("bedrock-runtime", region_name="us-east-1",
            aws_access_key_id="testing", aws_secret_access_key="testing")
        self.addCleanup(native.close)
        stubber = Stubber(native)
        stubber.activate()
        self.addCleanup(stubber.deactivate)
        cases = gateway.load_cases()[:4]
        for index, case in enumerate(cases):
            response = product_test.response_for(case)
            response["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": "p04-native-" + str(index)}
            stubber.add_response(case["body"]["operation"], response,
                shared.expected_arguments(case["body"], self.snapshot["guardrail"]))
        self.sdk.side_effect = None
        self.sdk.return_value = native
        def audit(snapshot):
            now = time.time()
            return {'scope': 'aws-policy-audit', 'started_at': now, 'observed_at': now,
                    'resources': snapshot, 'aws_request_ids': [uuid4().hex for _ in range(3)]}
        client = self.client("aws", lambda: self.snapshot, audit)
        suite, rows = self.prepare(client)
        self.sdk.assert_not_called()
        for index in range(4):
            result, record = self.execute(client, suite, rows, index)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(record["provider_mode"], "aws")
            self.assertEqual(record["calls"][0]["provider_request_id"], "p04-native-" + str(index))
            self.assertEqual(set(record['policy_audits']), {'before', 'after'})
        stubber.assert_no_pending_responses()
        self.assertEqual(self.sdk.call_count, 4)
        for call in self.sdk.call_args_list:
            self.assertEqual(call.args, ("bedrock-runtime",))
            self.assertEqual(call.kwargs["region_name"], "us-east-1")
            self.assertEqual(call.kwargs["config"].retries["total_max_attempts"], 1)

    def test_bad_mode_region_and_reader_are_not_accepted(self):
        for overrides in ({"provider_mode": "automatic"}, {"region": "us-west-2"}, {"prepared_resources": {}}):
            args = dict(provider_mode="contract", region="us-east-1", control_token=shared.CONTROL, verifier_token=shared.VERIFIER)
            args.update(overrides)
            with self.assertRaises(ValueError):
                gateway.configured_app(self.path, **args)
        self.sdk.assert_not_called()

    def test_failed_pre_call_audit_prevents_runtime_dispatch(self):
        def audit(_snapshot):
            raise gateway.LedgerError(409)
        client = self.client('aws', lambda: self.snapshot, audit)
        suite, rows = self.prepare(client)
        result, record = self.execute(client, suite, rows, 0)
        self.assertEqual(result.status_code, 502)
        self.assertTrue(record['closed'])
        self.assertEqual(record['policy_audits'], {})
        self.assertEqual(record['calls'][0]['state'], 'error')
        self.assertIsNone(record['calls'][0]['dispatched_at'])
        self.sdk.assert_not_called()

    def test_failed_post_call_audit_preserves_dispatch_without_success_response(self):
        audits = []
        def audit(snapshot):
            audits.append(snapshot)
            if len(audits) == 2:
                raise gateway.LedgerError(409)
            now = time.time()
            return {'scope': 'aws-policy-audit', 'started_at': now, 'observed_at': now,
                    'resources': snapshot, 'aws_request_ids': [uuid4().hex for _ in range(3)]}
        client = self.client('aws', lambda: self.snapshot, audit)
        suite, rows = self.prepare(client)
        with patch.object(gateway, 'BedrockBackend') as backend:
            backend.return_value.return_value = {'ResponseMetadata': {
                'HTTPStatusCode': 200, 'RequestId': 'synthetic-runtime-request'}}
            result, record = self.execute(client, suite, rows, 0)
            backend.return_value.assert_called_once()
        self.assertEqual(result.status_code, 502)
        self.assertTrue(record['closed'])
        self.assertEqual(set(record['policy_audits']), {'before'})
        self.assertEqual(record['calls'][0]['state'], 'error')
        self.assertIsNotNone(record['calls'][0]['dispatched_at'])
        self.assertIsNone(record['calls'][0]['response'])
        self.assertEqual(len(audits), 2)
        self.sdk.assert_not_called()


if __name__ == "__main__":
    unittest.main()
