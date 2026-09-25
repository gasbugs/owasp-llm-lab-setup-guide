"""Deterministic contract responses, never evidence of AWS Guardrail execution.

Only the registered case selects this backend. Its ledger mode is contract and
it supplies no native RequestId. Learners cannot request this backend themselves.
"""
import json

from p04_backend import ProviderError
from p04_contract import canonical, validate_invocation


class ContractBackend:
    def __init__(self, case, guardrail):
        self.case, self.guardrail = json.loads(canonical(case)), json.loads(canonical(guardrail))

    def __call__(self, operation, payload):
        validate_invocation(operation, payload, body=self.case["body"], guardrail=self.guardrail)
        if self.case["provider_error"]:
            raise ProviderError("P04 synthetic service error")
        original = self.case["body"]["text"]
        email = "learner@example.com"
        detected = email in original
        output = original.replace(email, "{EMAIL}")
        usage = {"topicPolicyUnits": 0, "contentPolicyUnits": 0, "wordPolicyUnits": 0,
                 "sensitiveInformationPolicyUnits": 1, "sensitiveInformationPolicyFreeUnits": 0,
                 "contextualGroundingPolicyUnits": 0}
        assessment = {"sensitiveInformationPolicy": {"piiEntities": [
            {"type": "EMAIL", "match": email, "detected": True, "action": "ANONYMIZED"}
        ] if detected else [], "regexes": []}, "invocationMetrics": {
            "guardrailProcessingLatency": 1, "usage": usage,
            "guardrailCoverage": {"textCharacters": {"guarded": len(original), "total": len(original)}}}}
        if operation == "apply_guardrail":
            return {"usage": usage, "action": "GUARDRAIL_INTERVENED" if detected else "NONE",
                    "outputs": [{"text": output}] if detected else [], "assessments": [assessment]}
        return {"output": {"message": {"role": "assistant", "content": [{"text": output}]}},
                "stopReason": "end_turn", "usage": {"inputTokens": 15, "outputTokens": 15, "totalTokens": 30},
                "metrics": {"latencyMs": 1}, "trace": {"guardrail": {"modelOutput": [original],
                    "inputAssessment": {}, "outputAssessments": {self.guardrail["guardrailIdentifier"]: [assessment]}}}}
