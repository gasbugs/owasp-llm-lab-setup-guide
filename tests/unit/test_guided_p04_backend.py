"""Actual Boto3 request serialization using Stubber, never AWS network traffic."""
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from uuid import uuid4

import boto3
from botocore.stub import Stubber

GATEWAY = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway"
sys.path.insert(0, str(GATEWAY))
try:
    from p04_backend import BedrockBackend, ProviderError
    from p04_contract import expected_arguments
    from p04_invocation import Invocation, InvocationError
    from p04_ledger import GuardrailLedger
finally:
    sys.path.remove(str(GATEWAY))


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.body = {"operation": "converse", "text": " 정상 문장 "}
        self.guardrail = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}
        self.client = boto3.client("bedrock-runtime", region_name="us-east-1",
                                   aws_access_key_id="fixture", aws_secret_access_key="fixture")
        self.stubber = Stubber(self.client)
        self.addCleanup(self.client.close)
        self.addCleanup(self.stubber.deactivate)
        self.factory = Mock(return_value=self.client)
        self.response = {
            "output": {"message": {"role": "assistant", "content": [{"text": " 정상 문장 "}]}},
            "stopReason": "end_turn", "usage": {"inputTokens": 5, "outputTokens": 5, "totalTokens": 10},
            "metrics": {"latencyMs": 1},
            "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "native-" + uuid4().hex},
        }

    def backend(self):
        return BedrockBackend(self.body, self.guardrail, client_factory=self.factory)

    def test_converse_exact_arguments_and_native_response_are_preserved(self):
        args = expected_arguments(self.body, self.guardrail)
        self.stubber.add_response("converse", self.response, args)
        self.stubber.activate()
        self.assertEqual(self.backend()("converse", args), self.response)
        self.stubber.assert_no_pending_responses()
        kwargs = self.factory.call_args.kwargs
        self.assertEqual(kwargs["region_name"], "us-east-1")
        self.assertEqual(kwargs["config"].retries, {"total_max_attempts": 1})
        self.assertEqual(kwargs["config"].connect_timeout, 3)
        self.assertEqual(kwargs["config"].read_timeout, 20)

    def test_apply_uses_output_scope_without_converse(self):
        self.body["operation"] = "apply_guardrail"
        args = expected_arguments(self.body, self.guardrail)
        response = {"action": "NONE", "outputs": [], "assessments": [],
                    "usage": {"sensitiveInformationPolicyUnits": 1, "topicPolicyUnits": 0,
                              "contentPolicyUnits": 0, "wordPolicyUnits": 0,
                              "sensitiveInformationPolicyFreeUnits": 0, "contextualGroundingPolicyUnits": 0},
                    "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "apply-native"}}
        self.stubber.add_response("apply_guardrail", response, args)
        self.stubber.activate()
        self.assertEqual(self.backend()("apply_guardrail", args), response)
        self.stubber.assert_no_pending_responses()

    def test_missing_policy_never_creates_sdk_client(self):
        args = expected_arguments(self.body, self.guardrail)
        del args["guardrailConfig"]
        with self.assertRaises(ProviderError):
            self.backend()("converse", args)
        self.factory.assert_not_called()

    def test_wrong_operation_or_model_never_creates_sdk_client(self):
        args = expected_arguments(self.body, self.guardrail)
        with self.assertRaises(ProviderError):
            self.backend()("apply_guardrail", args)
        args["modelId"] = "other-model"
        with self.assertRaises(ProviderError):
            self.backend()("converse", args)
        self.factory.assert_not_called()

    def test_sdk_error_is_not_retried_or_exposed(self):
        args = expected_arguments(self.body, self.guardrail)
        self.stubber.add_client_error("converse", service_error_code="AccessDeniedException",
                                     service_message="private-provider-detail", expected_params=args)
        self.stubber.activate()
        with self.assertRaisesRegex(ProviderError, "^P04 Bedrock call failed$"):
            self.backend()("converse", args)
        self.assertEqual(self.factory.call_count, 1)
        self.stubber.assert_no_pending_responses()

    def test_missing_or_unsuccessful_native_metadata_is_not_fabricated(self):
        args = expected_arguments(self.body, self.guardrail)
        for metadata in ({}, {"HTTPStatusCode": 200}, {"HTTPStatusCode": 503, "RequestId": "request"},
                         {"HTTPStatusCode": True, "RequestId": "request"},
                         {"HTTPStatusCode": 200, "RequestId": ""}):
            client = Mock()
            client.converse.return_value = {**self.response, "ResponseMetadata": metadata}
            backend = BedrockBackend(self.body, self.guardrail, client_factory=Mock(return_value=client))
            with self.assertRaises(ProviderError):
                backend("converse", args)
            client.close.assert_called_once()

    def test_truncated_output_remains_raw_for_independent_grading(self):
        args = expected_arguments(self.body, self.guardrail)
        self.response["stopReason"] = "max_tokens"
        self.stubber.add_response("converse", self.response, args)
        self.stubber.activate()
        returned = self.backend()("converse", args)
        self.assertEqual(returned["stopReason"], "max_tokens")
        self.assertNotIn("task_completed", returned)
        self.assertNotIn("security_verdict", returned)

    def test_registered_body_and_policy_are_snapshots(self):
        original = deepcopy(self.body)
        args = expected_arguments(original, self.guardrail)
        backend = self.backend()
        self.body["text"] = "changed"
        self.guardrail["guardrailIdentifier"] = "other"
        self.stubber.add_response("converse", self.response, args)
        self.stubber.activate()
        self.assertEqual(backend("converse", args), self.response)

    def test_invalid_region_and_input_fail_before_client_creation(self):
        with self.assertRaises(ValueError):
            BedrockBackend(self.body, self.guardrail, region="eu-west-1", client_factory=self.factory)
        with self.assertRaises(ValueError):
            BedrockBackend({}, self.guardrail, client_factory=self.factory)
        self.factory.assert_not_called()

    def test_sdk_response_binds_to_closed_persistent_execution(self):
        args = expected_arguments(self.body, self.guardrail)
        self.stubber.add_response("converse", self.response, args)
        self.stubber.activate()
        with TemporaryDirectory() as folder:
            ledger = GuardrailLedger(Path(folder) / "state.sqlite3")
            suite, execution = str(uuid4()), str(uuid4())
            grant = ledger.register(suite, execution, "a" * 64, "b" * 64, "c" * 64,
                                    "aws", self.body, self.guardrail)
            provider = Invocation(ledger, self.backend(), lambda: "c" * 64)
            provider.invoke(grant["capability"], suite, execution, "converse", args)
            ledger.close(execution)
            saved = ledger.read(execution)
            self.assertTrue(saved["closed"])
            self.assertEqual(saved["calls"][0]["request"], args)
            self.assertEqual(saved["calls"][0]["response"], self.response)
            self.assertEqual(saved["calls"][0]["provider_request_id"], self.response["ResponseMetadata"]["RequestId"])


if __name__ == "__main__":
    unittest.main()
