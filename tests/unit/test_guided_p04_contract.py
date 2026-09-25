"""P04 SDK argument checks are independent of learner source hashes."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

import botocore.session
from botocore.validate import validate_parameters

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-bedrock-gateway/p04_contract.py"
spec = importlib.util.spec_from_file_location("p04_contract_test", SOURCE)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.guardrail = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}
        self.body = {"operation": "converse", "text": " 정상 문장 "}

    def check(self, args, operation=None):
        return contract.validate_invocation(operation or self.body["operation"], args,
                                            body=self.body, guardrail=self.guardrail)

    def test_both_exact_arguments_match_installed_sdk_shape(self):
        model = botocore.session.get_session().get_service_model("bedrock-runtime")
        for operation, api in (("converse", "Converse"), ("apply_guardrail", "ApplyGuardrail")):
            self.body["operation"] = operation
            args = contract.expected_arguments(self.body, self.guardrail)
            validate_parameters(args, model.operation_model(api).input_shape)
            self.assertEqual(self.check(args), args)

    def test_missing_foreign_policy_version_and_trace_are_rejected_not_repaired(self):
        original = contract.expected_arguments(self.body, self.guardrail)
        for field, value in (("guardrailIdentifier", "foreign"),
                             ("guardrailVersion", "1"), ("trace", "disabled")):
            args = deepcopy(original)
            args["guardrailConfig"][field] = value
            with self.assertRaises(ValueError):
                self.check(args)
        args = deepcopy(original)
        del args["guardrailConfig"]
        with self.assertRaises(ValueError):
            self.check(args)
        self.assertNotIn("guardrailConfig", args)

    def test_model_input_and_inference_changes_are_rejected(self):
        original = contract.expected_arguments(self.body, self.guardrail)
        changes = [
            ("modelId", "different-model"), ("messages", []), ("system", []),
            ("inferenceConfig", {"maxTokens": 512, "temperature": 0}),
            ("inferenceConfig", {"maxTokens": 128.0, "temperature": 0}),
            ("inferenceConfig", {"maxTokens": 128, "temperature": False}),
            ("inferenceConfig", {"maxTokens": 128, "temperature": "0"}),
            ("inferenceConfig", {"maxTokens": 128, "temperature": 0, "stopSequences": []}),
        ]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                args = deepcopy(original)
                args[field] = value
                with self.assertRaises(ValueError):
                    self.check(args)

    def test_key_order_and_numeric_zero_are_equivalent_without_mutating_input(self):
        args = dict(reversed(list(contract.expected_arguments(self.body, self.guardrail).items())))
        args["inferenceConfig"]["temperature"] = 0
        result = self.check(args)
        self.assertEqual(result, args)
        self.assertIs(type(args["inferenceConfig"]["temperature"]), int)
        self.assertIsNot(result, args)

    def test_apply_must_check_output_without_other_operations(self):
        self.body["operation"] = "apply_guardrail"
        original = contract.expected_arguments(self.body, self.guardrail)
        for key, value in (("source", "INPUT"), ("content", []), ("outputScope", "INTERVENTIONS")):
            args = deepcopy(original)
            args[key] = value
            with self.assertRaises(ValueError):
                self.check(args)
        with self.assertRaises(ValueError):
            self.check(original, "converse")

    def test_invalid_registered_body_never_authorizes_a_call(self):
        for body in ({}, [], True, {"operation": "converse", "text": ""},
                     {"operation": "converse", "text": "x", "approved": True}):
            self.body = body
            with self.assertRaises(ValueError):
                contract.validate_invocation("converse", {}, body=body, guardrail=self.guardrail)

    def test_extra_parameters_nonfinite_values_and_wrong_policy_are_rejected(self):
        args = contract.expected_arguments(self.body, self.guardrail)
        args["additionalModelRequestFields"] = {"anything": True}
        with self.assertRaises(ValueError):
            self.check(args)
        args = contract.expected_arguments(self.body, self.guardrail)
        args["inferenceConfig"]["temperature"] = float("nan")
        with self.assertRaises(ValueError):
            self.check(args)
        self.guardrail = {}
        with self.assertRaises(ValueError):
            self.check({})


if __name__ == "__main__":
    unittest.main()
