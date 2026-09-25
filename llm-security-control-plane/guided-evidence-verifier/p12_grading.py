"""Aggregate server-owned P12 contracts using independent read-only evidence.

Call only with verifier-owned specifications and scaffold hashes. HTTP adapters
must accept a suite ID, never these grading parameters, from the caller.
"""
from copy import deepcopy
import hashlib
import json

from p12_results import EvidenceError, require
from p12_verification import verified_run_snapshot, verify_case_from_services

REQUIRED = {(200, None), (401, "authenticate"), (403, "authorize"),
            (403, "input_rail"), (403, "retrieval_rail"), (403, "output_rail"), (404, "retrieval")}


async def grade_run(origin, token, origins, tokens, *, suite_id, specifications,
                    documents, scaffold_files, now=None, transport=None):
    result = {"practice_id": "P12", "execution_id": "H12", "contract_version": 2,
              "suite_id": suite_id, "task_completed": False, "security_verdict": "ERR", "cases": []}
    current_case = None
    try:
        specifications, documents = deepcopy(specifications), deepcopy(documents)
        require(isinstance(specifications, list) and 8 <= len(specifications) <= 32, "incomplete grading contract")
        coverage, inputs = set(), []
        for spec in specifications:
            require(set(spec) == {"input", "status", "stop", "input_entities"}, "invalid grading fields")
            item = spec["input"]
            require(set(item) == {"case_id", "identity", "tenant", "message"}, "invalid case input")
            require(type(spec["status"]) is int and (spec["status"], spec["stop"]) in REQUIRED, "invalid expected path")
            entities = spec["input_entities"]
            require(isinstance(entities, dict) and all(name in {"EMAIL_ADDRESS", "KR_RRN"}
                and type(count) is int and count > 0 for name, count in entities.items()), "invalid privacy expectation")
            coverage.add((spec["status"], spec["stop"]))
            inputs.append(item)
        require(coverage == REQUIRED and any(spec["status"] == 200 and spec["input_entities"] for spec in specifications),
                "normal privacy and all stop paths required")
        contract = json.dumps({"cases": inputs, "documents": documents}, sort_keys=True, ensure_ascii=False, allow_nan=False)
        require(len(contract.encode()) <= 131072, "oversized grading contract")
        contract_digest = hashlib.sha256(contract.encode()).hexdigest()
        provider_ids, builds = set(), None
        async with verified_run_snapshot(origin, token, suite_id=suite_id,
                case_ids=[item["case_id"] for item in inputs], contract_digest=contract_digest,
                scaffold_files=scaffold_files, now=now, transport=transport) as snapshot:
            source = snapshot["binding"]["source_digest"]
            for spec, attempt in zip(specifications, snapshot["receipt"]["cases"]):
                current_case = spec["input"]["case_id"]
                verified = await verify_case_from_services(attempt, origins, tokens,
                    source_digest=source, expected_case=spec["input"], expected_status=spec["status"],
                    expected_stop=spec["stop"], now=now, transport=transport)
                if builds is None:
                    builds = verified["service_builds"]
                require(builds == verified["service_builds"], "product build changed between cases")
                privacy = [row for row in verified["ledgers"]["privacy"]["calls"] if row["stage"] == "input_privacy"]
                if privacy:
                    require(privacy[0]["evidence"]["entity_counts"] == spec["input_entities"], "privacy expectation mismatch")
                else:
                    require(not spec["input_entities"], "privacy stage missing")
                for grant in verified["ledgers"]["gateway"]["grants"]:
                    if grant["state"] == "completed":
                        identifier = grant["evidence"]["provider_request_id"]
                        require(identifier not in provider_ids, "provider evidence reused across cases")
                        provider_ids.add(identifier)
                result["cases"].append({"case_id": current_case, **verified["consistency"]})
        result.update(task_completed=True, security_verdict="PASS", source_digest=source,
                      contract_digest=contract_digest, provider_call_count=len(provider_ids))
    except Exception:
        # Do not expose transport exceptions, raw requests, or credentials.
        result.update(failed_case=current_case,
                      next_check="현재 실행의 원문 기록에서 미완성 단계와 서비스 오류를 확인하세요.")
    return result
