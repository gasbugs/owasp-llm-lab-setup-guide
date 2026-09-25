"""P12 cross-service evidence consistency, not a whole-problem completion verdict.

Caller must fetch these records with verifier credentials and bind the root receipt,
current builds and server-owned case contract separately. No learner answer hash.
"""
import hashlib
import math
import re
from uuid import UUID

ORDER = ("authenticate", "authorize", "input_privacy", "input_rail", "retrieval",
         "retrieval_rail", "main", "output_rail", "output_privacy")
ROLES = {"input_rail", "retrieval_rail", "main", "output_rail"}
MODEL = "us.amazon.nova-lite-v1:0"
EMPTY = hashlib.sha256(b"").hexdigest()


class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def stamp(value):
    require(type(value) in {int, float} and math.isfinite(value) and value > 0, "invalid timestamp")
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid digest")
    return value


def validate_case(attempt, ledgers, builds, *, source_digest, expected_case, expected_status, expected_stop, now):
    """Validate a completed normal/blocked case; all product failures raise EvidenceError."""
    try:
        result = _validate(attempt, ledgers, builds, source_digest, expected_status, expected_stop, now)
        _validate_inputs(attempt, ledgers, expected_case)
        return result
    except EvidenceError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise EvidenceError("incomplete or malformed P12 evidence") from None


def _validate_inputs(attempt, ledgers, case):
    require(isinstance(case, dict) and set(case) == {"case_id", "identity", "tenant", "message"},
            "server-owned input contract required")
    require(case["case_id"] == attempt["case_id"] and case["identity"] in {"reader", "visitor", "invalid"}
            and isinstance(case["message"], str) and bool(case["message"].strip())
            and isinstance(case["tenant"], str) and bool(case["tenant"]), "invalid input contract")
    records = {row["stage"]: row["evidence"] for service in ("context", "privacy") for row in ledgers[service]["calls"]}
    subject = None if case["identity"] == "invalid" else case["identity"]
    require(records["authenticate"]["subject"] == subject, "case principal mismatch")
    if "authorize" in records:
        proof = records["authorize"]
        require(proof["subject"] == subject and proof["requested_tenant"] == case["tenant"]
                and proof["required_scope"] == "knowledge:read", "case authorization mismatch")
    if "input_privacy" in records:
        require(records["input_privacy"]["input_digest"] == hashlib.sha256(case["message"].encode()).hexdigest(),
                "original case message mismatch")
    if "retrieval" in records:
        require(records["retrieval"]["authorized_tenant"] == case["tenant"], "case retrieval tenant mismatch")


def _validate(attempt, ledgers, builds, source_digest, expected_status, expected_stop, now):
    suite, execution_id = str(UUID(attempt["suite_id"])), str(UUID(attempt["execution_id"]))
    start, end = stamp(attempt["started_at"]), stamp(attempt["finished_at"])
    require(start <= end <= stamp(now) and now - end <= 900, "case time window mismatch")
    permitted = {200: {None}, 401: {"authenticate"}, 403: {"authorize", "input_rail", "retrieval_rail", "output_rail"}, 404: {"retrieval"}}
    require(type(expected_status) is int and expected_stop in permitted.get(expected_status, set()), "invalid expected contract")
    stages = ORDER if expected_stop is None else ORDER[:ORDER.index(expected_stop) + 1]
    lifecycle = attempt["lifecycle"]
    require(lifecycle["suite_id"] == suite and lifecycle["execution_id"] == execution_id
            and lifecycle["lifecycle_status"] == "finished", "lifecycle mismatch")
    execution = lifecycle["execution"]
    require(execution["source_digest"] == digest(source_digest) and execution["execution_status"] == "returned", "learner execution incomplete")
    result, calls = execution["result"], execution["calls"]
    require(type(result["status"]) is int and result["status"] == expected_status, "unexpected application result")
    require([call["stage"] for call in calls] == list(stages), "stage order mismatch")
    require(set(ledgers) == {"context", "privacy", "nemo", "gateway"}
            and set(lifecycle["closures"]) == set(ledgers), "missing service ledger")
    records = {}
    for service, ledger in ledgers.items():
        require(ledger["practice_id"] == "P12" and type(ledger["contract_version"]) is int
                and ledger["contract_version"] == 2 and ledger["suite_id"] == suite, "ledger scope mismatch")
        created = stamp(ledger["created" if service == "gateway" else "created_at"])
        closed = stamp(ledger["closed" if service == "gateway" else "closed_at"])
        require(start <= created <= closed <= end, "ledger time mismatch")
        require(lifecycle["closures"][service] == {"state": "closed", "closed_at": closed}, "closure mismatch")
        if service == "gateway":
            continue
        require(ledger["execution_ids"] == [execution_id], "foreign execution in ledger")
        build = builds[service]
        require(ledger["service_digest"] == digest(build["source_digest"]) == build["current_source_digest"], "service build mismatch")
        for row in ledger["calls"]:
            stage = row["stage"]
            owner = "nemo" if stage.endswith("_rail") else "privacy" if stage.endswith("_privacy") else "context"
            require(stage in stages and stage != "main" and owner == service and stage not in records, "extra or duplicate stage")
            require(row["suite_id"] == suite and row["execution_id"] == execution_id, "stage scope mismatch")
            require(row["state"] == "completed" and created <= stamp(row["started"]) <= stamp(row["finished"]) <= closed, "stage incomplete")
            require(row["evidence"]["service_digest"] == ledger["service_digest"], "stage build mismatch")
            records[stage] = row
    require(set(records) == set(stages) - {"main"}, "missing product stage")
    grants = ledgers["gateway"]["grants"]
    require(len(grants) == 4 and {grant["role"] for grant in grants} == ROLES, "invalid role grants")
    gateway = {grant["role"]: grant for grant in grants}
    provider_ids = set()
    previous = start
    for index, call in enumerate(calls, 1):
        stage = call["stage"]
        require(type(call["sequence"]) is int and call["sequence"] == index
                and call["state"] == "completed" and call["http_status"] == 200, "incomplete client call")
        require(previous <= stamp(call["started_at"]) <= stamp(call["finished_at"]) <= end, "client call time mismatch")
        previous = call["finished_at"]
        digest(call["input_digest"])
        if stage != "main":
            row, proof = records[stage], records[stage]["evidence"]
            require(row["input_digest"] == call["input_digest"] == proof["input_digest"], "input binding mismatch")
            require(call["started_at"] <= row["started"] <= row["finished"] <= call["finished_at"], "product outside client interval")
            require(all(proof[key] == value for key, value in call["evidence"].items()), "product projection mismatch")
            if stage in {"authenticate", "authorize"}:
                field = "authenticated" if stage == "authenticate" else "authorized"
                allowed = stage != expected_stop
                require(proof[field] is allowed and call["allowed"] is allowed, "identity decision mismatch")
            elif stage.endswith("_rail"):
                answer = "Yes" if stage == expected_stop else "No"
                require(proof["version"] == "0.22.0" and proof["framework"] == "nemo-guardrails"
                        and proof["classifier_answer"] == answer and proof["native_stop"] is (answer == "Yes")
                        and call["allowed"] is (answer == "No"), "invalid classifier result")
            elif stage.endswith("_privacy"):
                require(proof["framework"] == "microsoft-presidio" and proof["operator"] == "replace"
                        and proof["versions"] == {"presidio-analyzer": "2.2.362", "presidio-anonymizer": "2.2.362"}, "privacy product mismatch")
                require(call["output_digest"] == digest(proof["output_digest"]), "privacy output mismatch")
        if stage in ROLES:
            grant = gateway[stage]
            proof = call["evidence"] if stage == "main" else records[stage]["evidence"]["gateway"]
            require(grant["state"] == "completed" and call["started_at"] <= stamp(grant["reserved"])
                    <= stamp(grant["finished"]) <= call["finished_at"], "provider call incomplete")
            require(proof["request_digest"] == digest(grant["request_digest"])
                    and proof["capability_digest"] == digest(grant["token_digest"]), "provider request binding mismatch")
            evidence = grant["evidence"]
            require(evidence["actual_model_id"] == MODEL and proof["response_digest"] == digest(evidence["response_digest"]), "provider response mismatch")
            require(evidence.get("stop_reason") == "end_turn", "provider response did not finish normally")
            identifier = evidence["provider_request_id"]
            require(isinstance(identifier, str) and bool(identifier) and identifier not in provider_ids
                    and proof["provider_request_id"] == identifier, "provider ID mismatch")
            provider_ids.add(identifier)
            if stage != "main":
                answer = records[stage]["evidence"]["classifier_answer"]
                require(evidence["classifier_schema_valid"] is True and evidence["classifier_answer"] == answer
                        and evidence["response_digest"] == hashlib.sha256(answer.encode()).hexdigest(), "provider classifier invalid")
    for role, grant in gateway.items():
        require(grant["suite_id"] == suite and grant["execution_id"] == execution_id
                and grant["model"] == MODEL + "#p12-" + role, "grant scope mismatch")
        require(stamp(grant["issued"]) == ledgers["gateway"]["created"] and stamp(grant["expires"]) > grant["issued"], "grant validity mismatch")
        if role not in stages:
            require(grant["state"] == "closed_unused" and grant["reserved"] is None and grant["evidence"] is None
                    and grant["request_digest"] is None, "unexpected downstream call")
    def output(stage):
        return records[stage]["evidence"]["output_digest"]
    for source, target in (("input_privacy", "input_rail"), ("input_privacy", "retrieval"), ("retrieval", "retrieval_rail")):
        if target in records:
            require(output(source) == records[target]["input_digest"], "interstage text mismatch")
    if "main" in stages:
        main = gateway["main"]["evidence"]["main_input"]
        require(main["schema_valid"] is True, "Main input schema invalid")
        call = next(value for value in calls if value["stage"] == "main")
        require(main["prompt_digest"] == call["input_digest"], "Main prompt mismatch")
        for field, stage in (("question", "input_privacy"), ("context", "retrieval")):
            proof = records[stage]["evidence"]
            require(main[field + "_digest"] == output(stage) and type(main[field + "_bytes"]) is int
                    and main[field + "_bytes"] == proof["output_bytes"], "Main semantic input mismatch")
    if "retrieval" in records:
        proof = records["retrieval"]["evidence"]
        require(proof["query_executed"] is True and all(hit["tenant"] == proof["authorized_tenant"] for hit in proof["hits"]), "retrieval isolation mismatch")
        require(bool(proof["hits"]) is (expected_status != 404), "retrieval hit mismatch")
    require(type(ledgers["context"]["retrieval_count"]) is int
            and ledgers["context"]["retrieval_count"] == int("retrieval" in stages), "retrieval count mismatch")
    for target in ("output_rail", "output_privacy"):
        if target in records:
            require(records[target]["input_digest"] == gateway["main"]["evidence"]["response_digest"], "generated text mismatch")
    if expected_status == 200:
        proof = records["output_privacy"]["evidence"]
        require(result["text_digest"] == digest(proof["output_digest"])
                and type(result["text_bytes"]) is int and result["text_bytes"] == proof["output_bytes"], "final result mismatch")
    else:
        require(result["text_digest"] == EMPTY and type(result["text_bytes"]) is int and result["text_bytes"] == 0, "denied response contains text")
    return {"evidence_consistent": True, "stages": list(stages), "retrieval_count": ledgers["context"]["retrieval_count"],
            "provider_calls": len(provider_ids)}
