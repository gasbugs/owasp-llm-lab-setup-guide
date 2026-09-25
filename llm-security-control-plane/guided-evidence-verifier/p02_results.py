"""Compare P02 learner output to independently obtained closed provider evidence."""
import hashlib
import json
import math
import re


class EvidenceError(ValueError):
    pass


def require(condition):
    if not condition:
        raise EvidenceError("P02 evidence does not meet the current case contract")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_digest(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode())


def stamp(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def verify_case(expected, execution, ledger, source_evidence, *, source_digest, runner_digest, bucket, provider_mode="aws"):
    """Expected inputs and build digests belong to the verifier, not a Browser submission.

    The caller separately validates the full suite, resource configuration, freshness
    at read time and unchanged build snapshots. This function awards no course verdict.
    """
    try:
        digest(source_digest)
        digest(runner_digest)
        require(ledger["practice_id"] == "P02" and ledger["activity_id"] == "H02"
                and ledger["contract_version"] == "p02-document-v1" and ledger["closed"] is True)
        require(execution["lifecycle_status"] == "finished" and execution["closure"]["state"] == "closed")
        for key in ("suite_id", "execution_id"):
            require(ledger[key] == expected[key] == execution[key])
        for key, value in (("source_digest", source_digest), ("runner_digest", runner_digest)):
            require(ledger[key] == value == execution[key])
        start, end = stamp(ledger["started_at"]), stamp(ledger["closed_at"])
        require(0 <= end - start < 180 and execution["started_at"] == start and execution["closure"]["closed_at"] == end)
        worker = execution["execution"]
        require(worker["source_digest"] == source_digest)
        calls, worker_calls = ledger["calls"], worker["calls"]
        require(isinstance(calls, list) and isinstance(worker_calls, list))
        if expected["valid"] is False:
            require(worker["execution_status"] == "rejected" and calls == [] and worker_calls == [])
            return {"execution_id": expected["execution_id"], "case_verified": True, "calls": 0}
        require(expected["valid"] is True and worker["execution_status"] == "returned")
        require(len(calls) == 2 and len(worker_calls) == 2)
        key = f"h02/knowledge/{expected['execution_id']}.md"
        text = expected["body"]["body"]
        raw = f"# {expected['body']['title']}\n\n{text}\n".encode()
        payloads = [{"key": key, "content": raw.decode()}, {"text": text}]
        previous_end = start
        identities = []
        for index, (call, local, operation, payload) in enumerate(zip(calls, worker_calls, ("store_source", "embed"), payloads), 1):
            require(call["execution_id"] == expected["execution_id"] and call["operation"] == operation
                    and type(call["sequence"]) is int and call["sequence"] == index and call["state"] == "complete")
            call_start, call_end = stamp(call["started_at"]), stamp(call["finished_at"])
            require(previous_end <= call_start <= call_end <= end)
            previous_end = call_end
            require(call["request_digest"] == json_digest(payload))
            require(local["operation"] == operation and local["state"] == "complete"
                    and type(local["http_status"]) is int and local["http_status"] == 200
                    and local["request_digest"] == call["request_digest"]
                    and local["response_digest"] == json_digest(call["response"]))
            identity = call["provider_request_id"]
            require(isinstance(identity, str) and 0 < len(identity) <= 256 and identity not in identities
                    and identity == call["response"]["provider_request_id"])
            identities.append(identity)
        stored, embedding = calls[0]["response"], calls[1]["response"]
        require(provider_mode in {"aws", "contract"} and stored["provider_mode"] == provider_mode
                and embedding["provider_mode"] == provider_mode and source_evidence["provider_mode"] == provider_mode)
        require(stored["object_key"] == key and stored["object_uri"] == f"s3://{bucket}/{key}"
                and stored["source_digest"] == sha(raw) and type(stored["source_bytes"]) is int
                and stored["source_bytes"] == len(raw))
        require(source_evidence["object_key"] == key and source_evidence["source_digest"] == sha(raw)
                and type(source_evidence["source_bytes"]) is int and source_evidence["source_bytes"] == len(raw))
        read_id = source_evidence["provider_request_id"]
        require(isinstance(read_id, str) and 0 < len(read_id) <= 256 and read_id not in identities)
        require(embedding["model_id"] == "amazon.titan-embed-text-v2:0" and embedding["input_digest"] == sha(text.encode())
                and type(embedding["embedding_dimension"]) is int and embedding["embedding_dimension"] == 1024
                and type(embedding["input_token_count"]) is int and embedding["input_token_count"] > 0)
        norm = embedding["embedding_norm"]
        require(type(norm) in (int, float) and math.isfinite(norm) and abs(norm - 1) < 0.001)
        digest(embedding["vector_digest"])
        require(worker["result"] == {"source": stored, "embedding": embedding})
        return {"execution_id": expected["execution_id"], "case_verified": True, "calls": 2,
                "provider_request_ids": identities, "source_read_request_id": read_id}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        raise EvidenceError("P02 evidence does not meet the current case contract") from None
