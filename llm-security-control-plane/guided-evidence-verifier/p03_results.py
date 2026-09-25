"""Compare P03 worker behavior with independently fetched, closed call evidence.

This case checker does not award course completion. Its caller owns the suite,
resource bindings, build snapshots and read-only HTTP evidence collection.
"""
import hashlib
import json
import math
import re
from uuid import UUID


class EvidenceError(ValueError):
    pass


def require(condition):
    if not condition:
        raise EvidenceError("P03 evidence does not meet the current case contract")


def json_digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()).hexdigest()


def stamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    return value


def identity(value):
    require(isinstance(value, str) and 0 < len(value.strip()) <= 256)
    return value


def native(response, expected, provider_ids):
    require(response["provider_mode"] == "aws")
    for key in ("ingestion_job_id", "provider_ingestion_job_id", "knowledge_base_id", "data_source_id"):
        expected_key = "current_job_id" if key == "ingestion_job_id" else key
        require(identity(response[key]) == identity(expected[expected_key]))
    request_id = identity(response["provider_request_id"])
    require(request_id not in provider_ids)
    provider_ids.append(request_id)


def verify_case(expected, execution, ledger, *, source_digest, runner_digest, now, provider_mode):
    """All expected fields and digests are server-owned, never Browser arguments."""
    try:
        require(provider_mode in {"aws", "contract"})
        for value in (source_digest, runner_digest):
            require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
        require(ledger["practice_id"] == "P03" and ledger["activity_id"] == "H03"
                and ledger["contract_version"] == "p03-search-v1" and ledger["closed"] is True)
        require(execution["lifecycle_status"] == "finished" and execution["closure"]["state"] == "closed")
        for key in ("suite_id", "execution_id"):
            require(str(UUID(expected[key])) == expected[key] == execution[key] == ledger[key])
        require(ledger["current_job_id"] == expected["current_job_id"])
        for key, value in (("source_digest", source_digest), ("runner_digest", runner_digest)):
            require(execution[key] == ledger[key] == value)
        start, end = stamp(ledger["started_at"]), stamp(ledger["closed_at"])
        require(start <= end <= stamp(now) and now - start < 180)
        require(execution["started_at"] == start and execution["closure"]["closed_at"] == end)
        worker = execution["execution"]
        require(worker["source_digest"] == source_digest)
        calls, local_calls = ledger["calls"], worker["calls"]
        require(isinstance(calls, list) and isinstance(local_calls, list) and 1 <= len(calls) <= 2
                and len(calls) == len(local_calls))
        previous_end, observations, provider_ids = start, [], []
        for index, (call, local) in enumerate(zip(calls, local_calls), 1):
            operation = ("job_status", "retrieve")[index - 1]
            require(call["execution_id"] == expected["execution_id"] and call["operation"] == operation
                    and type(call["sequence"]) is int and call["sequence"] == index)
            begin, finish = stamp(call["started_at"]), stamp(call["finished_at"])
            require(previous_end <= begin <= finish <= end)
            previous_end = finish
            require(call["request_digest"] == local["request_digest"] == json_digest({})
                    and local["operation"] == operation)
            if call["state"] == "error":
                require(index == len(calls) and expected["outcome"] == "provider_error"
                        and expected["failed_operation"] == operation and provider_mode == "contract"
                        and local["state"] == "error" and local["http_status"] == 502
                        and call["response"] is None and call["observation_id"] is None
                        and call["provider_request_id"] is None)
                continue
            require(call["state"] == local["state"] == "complete" and type(local["http_status"]) is int
                    and local["http_status"] == 200 and local["response_digest"] == json_digest(call["response"]))
            response = call["response"]
            observed = identity(response["observation_id"])
            require(observed == call["observation_id"] and observed not in observations)
            observations.append(observed)
            require(response["provider_mode"] == provider_mode
                    and call["provider_request_id"] == response.get("provider_request_id"))
            if provider_mode == "aws":
                native(response, expected, provider_ids)
        state = calls[0]["response"]
        outcome = expected["outcome"]
        if outcome == "provider_error":
            require(worker["execution_status"] == "service_error" and calls[-1]["state"] == "error")
            if len(calls) == 2:
                require(state["ingestion_job_id"] == expected["current_job_id"] and state["status"] == "COMPLETE")
        else:
            require(calls[0]["state"] == "complete")
            if provider_mode == "contract":
                payload = {key: value for key, value in state.items() if key != "observation_id"}
                require(json_digest(payload) == json_digest(expected["status_response"]))
            same_job = state.get("ingestion_job_id") == expected["current_job_id"]
            status = state.get("status")
            valid_status = isinstance(status, str) and status in {"QUEUED", "STARTING", "IN_PROGRESS", "COMPLETE"}
            if outcome == "rejected":
                require(len(calls) == 1 and worker["execution_status"] == "rejected" and not (same_job and valid_status))
            elif outcome == "waiting":
                require(len(calls) == 1 and same_job and status in {"QUEUED", "STARTING", "IN_PROGRESS"}
                        and worker["execution_status"] == "returned"
                        and worker["result"] == {"status": "waiting", "result": None})
            else:
                require(outcome == "ready" and len(calls) == 2 and same_job and status == "COMPLETE"
                        and worker["execution_status"] == "returned" and calls[1]["state"] == "complete")
                result = calls[1]["response"]
                require(json_digest(worker["result"]) == json_digest({"status": "ready", "result": result}))
                require(result["ingestion_job_id"] == expected["current_job_id"])
                if provider_mode == "aws":
                    recheck = result["status_observation"]
                    native(recheck, expected, provider_ids)
                    for status_result in (state, recheck):
                        failed = status_result["statistics"].get("numberOfDocumentsFailed")
                        require(status_result["status"] == "COMPLETE"
                                and type(failed) is int and failed == 0)
                results, allowed = result["results"], expected["source_uris"]
                require(isinstance(results, list) and 1 <= len(results) <= 3
                        and isinstance(allowed, list) and len(allowed) > 0)
                for item in results:
                    score = item["score"]
                    require(item["location"]["type"] == "S3" and item["location"]["s3Location"]["uri"] in allowed
                            and isinstance(item["content"]["text"], str) and item["content"]["text"].strip()
                            and type(score) in (int, float) and math.isfinite(score)
                            and isinstance(item.get("metadata", {}), dict))
        return {"execution_id": expected["execution_id"], "case_verified": True, "outcome": outcome,
                "calls": len(calls), "observation_ids": observations, "provider_request_ids": provider_ids}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, IndexError):
        raise EvidenceError("P03 evidence does not meet the current case contract") from None
