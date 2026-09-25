"""Whole-suite P04 checks on independently collected snapshots.

The caller must collect authenticated current runner/Gateway evidence and check
continuity around collection. This pure check is not an HTTP grading endpoint,
an AWS policy audit, or proof that contract fixtures ran on AWS.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from uuid import UUID

from p04_results import EvidenceError, require, sha, timestamp, verify_execution_binding
from p04_product import verify_product_response

FILES = ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")


class SuiteContract:
    def __init__(self, runner_root):
        root = Path(runner_root)
        spec = importlib.util.spec_from_file_location("p04_verifier_owned_cases", root / "cases.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.cases = module.cases()
        require(module.CONTRACT_VERSION == "p04-guardrail-v1" and len(self.cases) == 27)
        require(len({case["case_id"] for case in self.cases}) == 27)
        self.contract_digest = sha(self.cases)
        self.files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}
        self.runner_digest = hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()

    def verify(self, suite_id, root, registration, build, records, resources, *, now):
        try:
            return self._verify(suite_id, root, registration, build, records, resources, now=now)
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
            raise EvidenceError("P04 whole-suite evidence is missing or inconsistent") from None

    def _verify(self, suite_id, root, registration, build, records, resources, *, now):
        require(str(UUID(suite_id)) == suite_id)
        for value in (root, registration):
            require(value["practice_id"] == "P04" and value["activity_id"] == "H04"
                    and value["contract_version"] == "p04-guardrail-v1" and value["suite_id"] == suite_id)
        require(root["run_state"] == "finished" and registration["state"] == "prepared")
        started, finished = timestamp(root["started_at"]), timestamp(root["finished_at"])
        prepared = timestamp(registration["prepared_at"])
        registered = timestamp(registration["started_at"])
        require(started <= registered <= prepared <= finished <= timestamp(now))
        require(prepared - registered < 30 and finished - started < 180 and now - started < 900)
        require(sha(build) == sha(root["build"]) == sha(root["final_build"]))
        require(build["runner_files"] == self.files and build["runner_digest"] == self.runner_digest)
        require(build["contract_digest"] == registration["contract_digest"] == self.contract_digest)
        source = build["source_digest"]
        require(isinstance(source, str) and re.fullmatch(r"[0-9a-f]{64}", source))
        require(sha(resources) == sha(registration["resources"]))
        rows, bindings = root["cases"], registration["cases"]
        require(isinstance(rows, list) and isinstance(bindings, list) and isinstance(records, list))
        require(len(rows) == len(bindings) == len(records) == len(self.cases))
        require(all(set(row) == {"case_id", "execution_id", "execution"} for row in rows))
        require(all(set(row) == {"case_id", "execution_id"} for row in bindings))
        require([row["case_id"] for row in rows] == [case["case_id"] for case in self.cases])
        require(bindings == [{key: row[key] for key in ("case_id", "execution_id")} for row in rows])
        ids = [row["execution_id"] for row in rows]
        require(len(set(ids)) == len(ids) and all(str(UUID(value)) == value for value in ids))
        outcomes, observations, native_ids = [], set(), set()
        previous_end = prepared
        for case, row, record in zip(self.cases, rows, records):
            require(previous_end <= timestamp(record["started_at"]) <= timestamp(record["closed_at"]) <= finished)
            previous_end = record["closed_at"]
            checked = verify_execution_binding(case, row["execution"], record, suite_id=suite_id,
                execution_id=row["execution_id"], source_digest=source, runner_digest=self.runner_digest,
                resources=resources, now=now)
            for seen, value in ((observations, checked["observation_id"]),
                                (native_ids, checked["provider_request_id"])):
                if value is not None:
                    require(value not in seen)
                    seen.add(value)
            for value in checked.get('policy_audit_request_ids', []):
                require(value not in native_ids)
                native_ids.add(value)
            effect = None
            if case["backend"] == "provider":
                effect = verify_product_response(case, checked["response"], resources["guardrail"])
            outcomes.append({"case_id": case["case_id"], "execution_id": row["execution_id"],
                             "binding": checked, "product": effect})
        require(sum(row["product"] is not None for row in outcomes) == 4)
        return {"suite_contract_verified": True, "provider_mode": resources["provider_mode"],
                "source_digest": source, "runner_digest": self.runner_digest,
                "suite_id": suite_id, "cases": outcomes}
