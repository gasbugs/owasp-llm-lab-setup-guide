"""P04 product-response checks, applied only after independent execution binding.

Response shapes: Boto3 bedrock-runtime apply_guardrail and converse documentation.
This module neither authenticates evidence nor assigns whole-suite PASS/completion.
"""
import json

from p04_results import EvidenceError, require

EMAIL = "learner@example.com"


def model_text(raw, original):
    if raw.strip() == original.strip():
        return raw

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    # Nova's native trace can contain its JSON message envelope, not plain text.
    # Accept only the observed text-only assistant shape; no arbitrary JSON search.
    envelope = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(envelope, dict) and set(envelope) == {'message'})
    message = envelope['message']
    require(isinstance(message, dict) and set(message) == {'role', 'content'}
            and message['role'] == 'assistant')
    return texts(message['content'])


def texts(blocks):
    require(isinstance(blocks, list))
    require(all(isinstance(block, dict) and set(block) == {"text"}
                and isinstance(block["text"], str) for block in blocks))
    return "".join(block["text"] for block in blocks)


def actions(value):
    found = []
    if isinstance(value, dict):
        if "action" in value:
            require(value["action"] in ("NONE", "BLOCKED", "ANONYMIZED"))
            found.append(value["action"])
        for child in value.values():
            found.extend(actions(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(actions(child))
    return found


def pii(assessments, guardrail, *, require_usage):
    require(isinstance(assessments, list) and 1 <= len(assessments) <= 8)
    entities = []
    units = 0
    for assessment in assessments:
        require(isinstance(assessment, dict))
        details = assessment.get("appliedGuardrailDetails")
        if details is not None:
            require(details["guardrailId"] == guardrail["guardrailIdentifier"]
                    and details["guardrailVersion"] == guardrail["guardrailVersion"])
        policy = assessment.get("sensitiveInformationPolicy", {})
        require(isinstance(policy, dict))
        rows = policy.get("piiEntities", [])
        require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows))
        entities.extend(rows)
        require(all(action in ("NONE", "ANONYMIZED") for action in actions(assessment)))
        if require_usage:
            value = assessment["invocationMetrics"]["usage"]["sensitiveInformationPolicyUnits"]
            require(type(value) is int and value >= 0)
            units += value
    if require_usage:
        require(units > 0)
    return entities


def verify_product_response(case, response, guardrail):
    try:
        return _verify(case, response, guardrail)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise EvidenceError("P04 Guardrail output effect is unproven or inconsistent") from None


def _verify(case, response, guardrail):
    require(case["backend"] == "provider" and case["expected"] == "returned"
            and case["provider_error"] is False and guardrail["guardrailVersion"] == "DRAFT")
    operation, original = case["body"]["operation"], case["body"]["text"]
    require(operation in ("apply_guardrail", "converse") and isinstance(original, str) and bool(original.strip()))
    risk = case["case_id"] == operation + "-email"
    require(risk or case["case_id"] == operation + "-normal")
    require(original.count(EMAIL) == (1 if risk else 0))
    if operation == "apply_guardrail":
        require(response["action"] == ("GUARDRAIL_INTERVENED" if risk else "NONE"))
        units = response["usage"]["sensitiveInformationPolicyUnits"]
        require(type(units) is int and units > 0)
        assessed = response["assessments"]
        entities = pii(assessed, guardrail, require_usage=False)
        output = texts(response["outputs"])
        if not risk:
            # NONE with no replacement means the supplied input remains unchanged.
            require(output in ("", original))
    else:
        require(response["stopReason"] in (("end_turn", "guardrail_intervened") if risk else ("end_turn",)))
        usage = response["usage"]
        for field in ("inputTokens", "outputTokens", "totalTokens"):
            require(type(usage[field]) is int and usage[field] > 0)
        require(usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"])
        message = response["output"]["message"]
        require(message["role"] == "assistant")
        output = texts(message["content"])
        trace = response["trace"]["guardrail"]
        mapping = trace["outputAssessments"]
        require(isinstance(mapping, dict) and set(mapping) == {guardrail["guardrailIdentifier"]})
        assessed = mapping[guardrail["guardrailIdentifier"]]
        entities = pii(assessed, guardrail, require_usage=True)
        input_assessment = trace.get("inputAssessment", {})
        require(isinstance(input_assessment, dict))
        require(all(action == "NONE" for action in actions(input_assessment)))
        if "modelOutput" in trace:
            require(isinstance(trace["modelOutput"], list)
                    and all(isinstance(value, str) for value in trace["modelOutput"]))
            # Optional trace detail may be empty even with a verified normal output.
            # Native output assessments and the final message remain mandatory.
            if trace["modelOutput"]:
                require(model_text("".join(trace["modelOutput"]), original).strip() == original.strip())
        if not risk:
            require(output.strip() == original.strip())
    if risk:
        matches = [row for row in entities if row.get("type") == "EMAIL"
                   and row.get("match") == EMAIL and row.get("detected") is True
                   and row.get("action") == "ANONYMIZED"]
        require(len(matches) == 1)
        require(sum(action == "ANONYMIZED" for action in actions(assessed)) == 1)
        require(output.strip() == original.replace(EMAIL, "{EMAIL}").strip() and EMAIL not in output)
    else:
        require(all(action == "NONE" for action in actions(assessed)))
        require(not any(row.get("detected") is True for row in entities))
    return {"product_result_verified": True, "operation": operation,
            "effect": "email_anonymized" if risk else "unchanged", "model_called": operation == "converse"}
