"""Read-only P04 execution binding checks. These do not grade Guardrail effectiveness."""
import hashlib
import json
import math
import re
from uuid import UUID


class EvidenceError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition):
    if not condition:
        raise EvidenceError("P04 execution evidence is missing or inconsistent")


def timestamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    return value


def verify_policy_audit(proof, resources, *, earliest, latest):
    require(isinstance(proof, dict) and set(proof) == {
        'scope', 'started_at', 'observed_at', 'resources', 'aws_request_ids'})
    start, end = timestamp(proof['started_at']), timestamp(proof['observed_at'])
    require(proof['scope'] == 'aws-policy-audit' and earliest <= start <= end <= latest
            and end - start < 12 and sha(proof['resources']) == sha(resources))
    ids = proof['aws_request_ids']
    require(isinstance(ids, list) and len(ids) == 3
            and all(isinstance(value, str) and value.isascii() and 1 <= len(value) <= 256 for value in ids)
            and len(set(ids)) == 3)
    return list(ids)


def arguments(body, guardrail):
    """Independent contract reconstruction; never forwards or repairs learner requests."""
    if (not isinstance(body, dict) or set(body) != {"operation", "text"}
            or body["operation"] not in ("apply_guardrail", "converse")
            or not isinstance(body["text"], str) or not 1 <= len(body["text"]) <= 1000
            or not body["text"].strip()):
        return None
    if body["operation"] == "apply_guardrail":
        return {**guardrail, "source": "OUTPUT", "content": [{"text": {"text": body["text"]}}],
                "outputScope": "FULL"}
    return {"modelId": "us.amazon.nova-lite-v1:0",
            "system": [{"text": "사용자 문장을 그대로 한 번만 출력하세요. 다른 설명을 덧붙이지 마세요."}],
            "messages": [{"role": "user", "content": [{"text": body["text"]}]}],
            "inferenceConfig": {"maxTokens": 128, "temperature": 0.0},
            "guardrailConfig": {**guardrail, "trace": "enabled"}}


def verify_execution_binding(case, receipt, record, *, suite_id, execution_id,
                             source_digest, runner_digest, resources, now):
    try:
        return _verify(case, receipt, record, suite_id=suite_id, execution_id=execution_id,
                       source_digest=source_digest, runner_digest=runner_digest, resources=resources, now=now)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise EvidenceError("P04 execution evidence is missing or inconsistent") from None


def _verify(case, receipt, record, *, suite_id, execution_id, source_digest, runner_digest, resources, now):
    require(str(UUID(suite_id)) == suite_id and str(UUID(execution_id)) == execution_id)
    require(set(resources) == {"provider_mode", "guardrail", "guardrail_arn", "policy_digest"})
    require(set(case) == {"case_id", "backend", "body", "expected", "provider_error"})
    for value in (source_digest, runner_digest, resources["policy_digest"]):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))
    guardrail = resources["guardrail"]
    require(isinstance(guardrail, dict) and set(guardrail) == {"guardrailIdentifier", "guardrailVersion"})
    identifier = guardrail["guardrailIdentifier"]
    require(isinstance(identifier, str) and identifier.isascii() and 1 <= len(identifier) <= 2048
            and identifier.strip() and guardrail["guardrailVersion"] == "DRAFT")
    require(resources["provider_mode"] in ("aws", "contract"))
    if resources["provider_mode"] == "contract":
        require(identifier == "p04contract" and resources["guardrail_arn"] is None)
    else:
        arn = resources["guardrail_arn"]
        require(isinstance(arn, str) and re.fullmatch(
            r"arn:aws:bedrock:us-east-1:[0-9]{12}:guardrail/[a-z0-9]+", arn)
            and arn.rsplit("/", 1)[-1] == identifier)
    require(case["backend"] in ("provider", "contract") and type(case["provider_error"]) is bool)
    mode = resources["provider_mode"] if case["backend"] == "provider" else "contract"
    if mode == 'contract':
        require(record.get('policy_audits', {}) == {})
    require(record["provider_mode"] == mode and record["resource_digest"] == sha(resources))
    require(record["practice_id"] == "P04" and record["activity_id"] == "H04"
            and record["contract_version"] == "p04-guardrail-v1")
    for row in (receipt, record):
        require(row["suite_id"] == suite_id and row["execution_id"] == execution_id
                and row["source_digest"] == source_digest and row["runner_digest"] == runner_digest)
    require(record["closed"] is True and receipt["lifecycle_status"] == "finished")
    start, end = timestamp(record["started_at"]), timestamp(record["closed_at"])
    require(start <= end <= timestamp(now) and now - start < 900 and end - start < 180)
    require(timestamp(receipt["started_at"]) == start)
    require(timestamp(receipt["closure"]["closed_at"]) == end)
    require(receipt["closure"] == {"state": "closed", "closed_at": end})
    require(canonical(record["body"]) == canonical(case["body"]))
    require(canonical(record["guardrail"]) == canonical(guardrail))
    worker = receipt["execution"]
    require(worker["source_digest"] == source_digest)
    require(isinstance(record["calls"], list) and isinstance(worker["calls"], list))
    expected = arguments(case["body"], guardrail)
    if case["expected"] == "rejected":
        require(expected is None and case["backend"] == "contract" and not case["provider_error"])
        require(worker["execution_status"] == "rejected" and "result" not in worker)
        require(record["calls"] == [] and worker["calls"] == [])
        return {"execution_verified": True, "provider_mode": mode, "call_count": 0,
                "observation_id": None, "provider_request_id": None, "response": None}
    require(expected is not None and len(record["calls"]) == len(worker["calls"]) == 1)
    call, local = record["calls"][0], worker["calls"][0]
    require(type(local["http_status"]) is int)
    operation = case["body"]["operation"]
    require(call["execution_id"] == execution_id and call["operation"] == local["operation"] == operation)
    require(start <= timestamp(call["started_at"]) <= timestamp(call["dispatched_at"])
            <= timestamp(call["finished_at"]) <= end)
    require(str(UUID(call["observation_id"])) == call["observation_id"])
    request = json.loads(canonical(call["request"]))
    require(call["request_digest"] == local["request_digest"] == sha(request))
    if operation == "converse":
        config = request["inferenceConfig"]
        require(type(config["maxTokens"]) is int and type(config["temperature"]) in (int, float))
        if config["temperature"] == 0:
            config["temperature"] = 0.0
    require(canonical(request) == canonical(expected))
    response = call["response"]
    audit_ids = []
    if case["expected"] == "service_error":
        require(mode == "contract" and case["backend"] == "contract" and case["provider_error"])
        require(worker["execution_status"] == "service_error" and "result" not in worker)
        require(call["state"] == local["state"] == "error" and response is None
                and call["provider_request_id"] is None and local["http_status"] == 502
                and "response_digest" not in local)
    else:
        require(case["expected"] == "returned" and not case["provider_error"])
        require(call["state"] == local["state"] == "complete" and local["http_status"] == 200)
        require(worker["execution_status"] == "returned" and isinstance(response, dict))
        require(canonical(worker["result"]) == canonical(response) and local["response_digest"] == sha(response))
        if mode == "aws":
            metadata = response["ResponseMetadata"]
            provider_id = metadata["RequestId"]
            require(isinstance(provider_id, str) and provider_id.isascii() and 1 <= len(provider_id) <= 256)
            require(type(metadata["HTTPStatusCode"]) is int and metadata["HTTPStatusCode"] == 200
                    and call["provider_request_id"] == provider_id)
            audits = record['policy_audits']
            require(set(audits) == {'before', 'after'})
            audit_ids = verify_policy_audit(audits['before'], resources,
                earliest=call['started_at'], latest=call['dispatched_at'])
            audit_ids += verify_policy_audit(audits['after'], resources,
                earliest=call['dispatched_at'], latest=call['finished_at'])
            require(len(set(audit_ids + [provider_id])) == 7)
        else:
            require(call["provider_request_id"] is None)
    return {"execution_verified": True, "provider_mode": mode, "call_count": 1,
            "observation_id": call["observation_id"], "provider_request_id": call["provider_request_id"],
            "response": response, "policy_audit_request_ids": audit_ids}
