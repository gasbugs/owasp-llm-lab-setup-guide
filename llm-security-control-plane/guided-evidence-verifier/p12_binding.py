"""Bind a P12 root receipt to trusted contract and scaffold; not a course verdict."""
import hashlib
import json
from uuid import UUID

from p12_results import EvidenceError, digest, require, stamp

SCAFFOLD = {"Containerfile", "execution.py", "service_client.py", "workflow.py", "run_server.py"}


def validate_run_binding(receipt, build_info, *, suite_id, case_ids, contract_digest,
                         scaffold_files, now):
    """Expected inputs come from verifier configuration, never the Browser/receipt."""
    try:
        return _validate(receipt, build_info, suite_id, case_ids, contract_digest, scaffold_files, now)
    except EvidenceError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise EvidenceError("incomplete P12 run binding") from None


def _validate(receipt, info, suite, ids, contract, scaffold, now):
    require(isinstance(suite, str) and str(UUID(suite)) == suite, "invalid root suite")
    require(isinstance(ids, list) and 1 <= len(ids) <= 32
            and all(isinstance(value, str) and value for value in ids)
            and len(set(ids)) == len(ids), "invalid expected cases")
    require(set(scaffold) == SCAFFOLD, "trusted scaffold missing")
    for value in scaffold.values():
        digest(value)
    digest(contract)
    require(receipt["practice_id"] == info["practice_id"] == "P12"
            and receipt["execution_id"] == "H12"
            and type(receipt["contract_version"]) is int and receipt["contract_version"] == 2
            and type(info["contract_version"]) is int and info["contract_version"] == 2,
            "wrong problem contract")
    require(receipt["suite_id"] == suite and receipt["run_state"] == "finished", "run incomplete")
    start, end = stamp(receipt["started_at"]), stamp(receipt["finished_at"])
    require(start <= end <= stamp(now) and now - end <= 900, "run time window mismatch")
    build = receipt["build"]
    require(build == info["build"] == info["current_build"], "run source changed")
    require(build["contract_digest"] == contract and info["case_ids"] == ids, "case contract mismatch")
    files = build["files"]
    require(set(files) == SCAFFOLD | {"pipeline.py"}, "unexpected run files")
    for name, value in files.items():
        digest(value)
        if name != "pipeline.py":
            require(value == scaffold[name], "runner scaffold mismatch")
    require(build["source_digest"] == hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
            "build digest mismatch")
    attempts = receipt["cases"]
    require(isinstance(attempts, list) and [item["case_id"] for item in attempts] == ids,
            "missing duplicate or reordered cases")
    seen, previous = {suite}, start
    for attempt in attempts:
        for key in ("suite_id", "execution_id"):
            value = attempt[key]
            require(isinstance(value, str) and str(UUID(value)) == value and value not in seen,
                    "reused or invalid child execution")
            seen.add(value)
        begin, finish = stamp(attempt["started_at"]), stamp(attempt["finished_at"])
        require(previous <= begin <= finish <= end, "case outside run window")
        previous = finish
        lifecycle = attempt["lifecycle"]
        require(lifecycle["suite_id"] == attempt["suite_id"]
                and lifecycle["execution_id"] == attempt["execution_id"]
                and lifecycle["lifecycle_status"] == "finished", "child lifecycle mismatch")
        require(lifecycle["execution"]["source_digest"] == files["pipeline.py"], "child source mismatch")
    return {"run_bound": True, "suite_id": suite, "source_digest": files["pipeline.py"], "case_ids": list(ids)}
