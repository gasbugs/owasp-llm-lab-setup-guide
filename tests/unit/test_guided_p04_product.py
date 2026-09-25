"""Native-shaped response fixtures, not AWS calls or evidence of live enforcement."""
from copy import deepcopy
import json
import sys
import unittest
from unittest.mock import patch

import botocore.session
from botocore.validate import validate_parameters

from test_guided_p04_results import load, results
from test_guided_p04_suites import case_module

with patch.dict(sys.modules, {"p04_results": results}):
    product = load("p04_product")

GUARDRAIL = {"guardrailIdentifier": "p04fixture", "guardrailVersion": "DRAFT"}


def response_for(case):
    original = case["body"]["text"]
    risk = case["case_id"].endswith("-email")
    text = original.replace(product.EMAIL, "{EMAIL}") if risk else original
    usage = {"topicPolicyUnits": 0, "contentPolicyUnits": 0, "wordPolicyUnits": 0,
             "sensitiveInformationPolicyUnits": 1, "sensitiveInformationPolicyFreeUnits": 0,
             "contextualGroundingPolicyUnits": 0}
    assessment = {"sensitiveInformationPolicy": {"piiEntities": [
        {"type": "EMAIL", "match": product.EMAIL, "detected": True, "action": "ANONYMIZED"}
    ] if risk else [], "regexes": []}, "invocationMetrics": {"guardrailProcessingLatency": 1,
        "usage": usage, "guardrailCoverage": {"textCharacters": {"guarded": len(original), "total": len(original)}}}}
    if case["body"]["operation"] == "apply_guardrail":
        return {"usage": usage, "action": "GUARDRAIL_INTERVENED" if risk else "NONE",
                "outputs": [{"text": text}] if risk else [], "assessments": [assessment]}
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "stopReason": "end_turn", "usage": {"inputTokens": 15, "outputTokens": 15, "totalTokens": 30},
            "metrics": {"latencyMs": 1}, "trace": {"guardrail": {
                "modelOutput": [original], "inputAssessment": {},
                "outputAssessments": {GUARDRAIL["guardrailIdentifier"]: [assessment]}}}}


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.cases = case_module.cases()[:4]

    def verify(self, index, change=None):
        response = response_for(self.cases[index])
        if change:
            change(response)
        return product.verify_product_response(self.cases[index], response, GUARDRAIL)

    def test_fixture_shapes_match_installed_sdk_and_each_path_is_distinguished(self):
        service = botocore.session.get_session().get_service_model("bedrock-runtime")
        for index, case in enumerate(self.cases):
            response = response_for(case)
            operation = "ApplyGuardrail" if index < 2 else "Converse"
            validate_parameters(response, service.operation_model(operation).output_shape)
            outcome = self.verify(index)
            self.assertTrue(outcome["product_result_verified"])
            self.assertEqual(outcome["model_called"], index >= 2)
            self.assertEqual(outcome["effect"], "email_anonymized" if index % 2 else "unchanged")
            self.assertNotIn("task_completed", outcome)
            self.assertNotIn("security_verdict", outcome)

    def test_apply_anonymization_requires_exact_entity_match_and_action(self):
        for key, value in (("type", "PHONE"), ("match", "other@example.com"),
                           ("action", "NONE"), ("action", "BLOCKED"), ("detected", False),
                           ("detected", "true")):
            response = response_for(self.cases[1])
            response["assessments"][0]["sensitiveInformationPolicy"]["piiEntities"][0][key] = value
            with self.assertRaises(results.EvidenceError):
                product.verify_product_response(self.cases[1], response, GUARDRAIL)

    def test_missing_or_empty_assessment_does_not_prove_anonymization(self):
        for change in (lambda r: r.pop("assessments"), lambda r: r.update(assessments=[]),
                       lambda r: r["assessments"][0].update(sensitiveInformationPolicy={})):
            with self.assertRaises(results.EvidenceError):
                self.verify(1, change)

    def test_output_must_preserve_surrounding_text_and_remove_original_email(self):
        for text in ("", "죄송하지만 답할 수 없습니다.", "{EMAIL}",
                     self.cases[1]["body"]["text"], "담당자 이메일은 {EMAIL} 입니다. learner@example.com"):
            with self.assertRaises(results.EvidenceError):
                self.verify(1, lambda r: r.update(outputs=[{"text": text}]))

    def test_normal_apply_accepts_no_replacement_or_unchanged_text_only(self):
        original = self.cases[0]["body"]["text"]
        self.assertTrue(self.verify(0, lambda r: r.update(outputs=[{"text": original}]))["product_result_verified"])
        for change in (lambda r: r.update(action="GUARDRAIL_INTERVENED"),
                       lambda r: r.update(outputs=[{"text": "차단"}]),
                       lambda r: r["usage"].update(sensitiveInformationPolicyUnits=0)):
            with self.assertRaises(results.EvidenceError):
                self.verify(0, change)

    def test_converse_requires_output_not_input_assessment(self):
        response = response_for(self.cases[3])
        trace = response["trace"]["guardrail"]
        trace["inputAssessment"] = {GUARDRAIL["guardrailIdentifier"]: trace["outputAssessments"][GUARDRAIL["guardrailIdentifier"]][0]}
        trace["outputAssessments"] = {}
        with self.assertRaises(results.EvidenceError):
            product.verify_product_response(self.cases[3], response, GUARDRAIL)

    def test_optional_model_output_empty_or_absent_does_not_replace_native_evidence(self):
        for index in (2, 3):
            for change in (lambda r: r['trace']['guardrail'].update(modelOutput=[]),
                           lambda r: r['trace']['guardrail'].pop('modelOutput')):
                self.assertTrue(self.verify(index, change)['product_result_verified'])
            for value in (None, '', [None], ['different text']):
                with self.subTest(index=index, value=value), self.assertRaises(results.EvidenceError):
                    self.verify(index, lambda r: r['trace']['guardrail'].update(modelOutput=value))
        response = response_for(self.cases[3])
        response['trace']['guardrail'].update(modelOutput=[], outputAssessments={})
        with self.assertRaises(results.EvidenceError):
            product.verify_product_response(self.cases[3], response, GUARDRAIL)

    def test_output_assessment_binds_policy_and_uses_native_list_shape(self):
        for value in ({"other-policy": []}, {"p04fixture": {}}, {}):
            with self.assertRaises(results.EvidenceError):
                self.verify(3, lambda r: r["trace"]["guardrail"].update(outputAssessments=value))

    def test_nova_native_message_envelope_preserves_original_unmasked_text(self):
        original = self.cases[3]['body']['text']
        raw = json.dumps({'message': {'role': 'assistant', 'content': [{'text': original}]}}, ensure_ascii=False)
        self.assertTrue(self.verify(3, lambda r: r['trace']['guardrail'].update(modelOutput=[raw]))['product_result_verified'])
        for malformed in (raw.replace('assistant', 'user'),
                          raw.replace(original, original.replace(product.EMAIL, '{EMAIL}')),
                          raw.replace('"role": "assistant"', '"role": "user", "role": "assistant"'),
                          json.dumps({'message': {'role': 'assistant', 'content': [{'text': original}], 'tool': {}}}),
                          json.dumps({'message': {'role': 'assistant', 'content': [{'text': original}]}, 'extra': 1})):
            with self.subTest(raw=malformed), self.assertRaises(results.EvidenceError):
                self.verify(3, lambda r: r['trace']['guardrail'].update(modelOutput=[malformed]))

    def test_wrong_applied_policy_version_is_rejected(self):
        def change(response):
            response["trace"]["guardrail"]["outputAssessments"]["p04fixture"][0]["appliedGuardrailDetails"] = {
                "guardrailId": "p04fixture", "guardrailVersion": "1"}
        with self.assertRaises(results.EvidenceError):
            self.verify(3, change)

    def test_no_model_tokens_truncation_and_tool_call_are_not_normal_generation(self):
        for index in (2, 3):
            for reason in ("max_tokens", "tool_use", "content_filtered", "stop_sequence"):
                with self.assertRaises(results.EvidenceError):
                    self.verify(index, lambda r: r.update(stopReason=reason))
            for usage in ({"inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
                          {"inputTokens": 1, "outputTokens": 1, "totalTokens": 5}):
                with self.assertRaises(results.EvidenceError):
                    self.verify(index, lambda r: r.update(usage=usage))

    def test_explicit_anonymization_may_intervene_but_normal_case_must_finish(self):
        self.assertTrue(self.verify(3, lambda r: r.update(stopReason="guardrail_intervened"))["product_result_verified"])
        with self.assertRaises(results.EvidenceError):
            self.verify(2, lambda r: r.update(stopReason="guardrail_intervened"))

    def test_converse_refusal_pre_masked_generation_and_lost_trace_do_not_pass(self):
        for change in (
            lambda r: r["output"]["message"].update(content=[{"text": "죄송합니다."}]),
            lambda r: r["trace"]["guardrail"].update(modelOutput=["담당자 이메일은 {EMAIL} 입니다."]),
            lambda r: r.pop("trace"),
            lambda r: r["trace"]["guardrail"]["outputAssessments"]["p04fixture"][0].pop("invocationMetrics"),
        ):
            with self.assertRaises(results.EvidenceError):
                self.verify(3, change)

    def test_duplicate_anonymization_or_other_block_is_not_the_requested_effect(self):
        for change in (
            lambda a: a["sensitiveInformationPolicy"]["piiEntities"].append(
                deepcopy(a["sensitiveInformationPolicy"]["piiEntities"][0])),
            lambda a: a.update(contentPolicy={"filters": [{"type": "VIOLENCE", "action": "BLOCKED"}]}),
        ):
            response = response_for(self.cases[1])
            change(response["assessments"][0])
            with self.assertRaises(results.EvidenceError):
                product.verify_product_response(self.cases[1], response, GUARDRAIL)

    def test_synthetic_boundary_case_cannot_be_presented_as_a_native_product_case(self):
        case = deepcopy(self.cases[0])
        case["backend"] = "contract"
        with self.assertRaises(results.EvidenceError):
            product.verify_product_response(case, response_for(case), GUARDRAIL)


if __name__ == "__main__":
    unittest.main()
