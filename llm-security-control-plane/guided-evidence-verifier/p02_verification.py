"""Read-only P02 suite collection and completion checks against immutable local contracts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time
from uuid import UUID

from p02_results import EvidenceError, digest, require, stamp, verify_case

FILES = ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")


class Verification:
    def __init__(self, runner_root, app_url, gateway_url, app_token, gateway_token):
        root = Path(runner_root)
        spec = importlib.util.spec_from_file_location("p02_server_owned_cases", root / "cases.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.cases = module.cases()
        self.contract_digest = hashlib.sha256(json.dumps(self.cases, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        self.files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}
        self.runner_digest = hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()
        self.app_url, self.gateway_url = app_url.rstrip("/"), gateway_url.rstrip("/")
        self.app_token, self.gateway_token = app_token, gateway_token

    def collect(self, suite_id, client):
        require(str(UUID(suite_id)) == suite_id)
        deadline = time.monotonic() + 180

        def get(origin, path, token):
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            with client.stream("GET", origin + path, headers={"Authorization": "Bearer " + token},
                               timeout=min(95 if path.endswith("/resources") else 5, remaining)) as response:
                require(response.status_code == 200)
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    require(len(raw) <= 1048576 and time.monotonic() < deadline)
            result = json.loads(raw)
            require(isinstance(result, dict))
            return result

        def app(path):
            return get(self.app_url, path, self.app_token)

        def gateway(path):
            return get(self.gateway_url, "/v1/p02" + path, self.gateway_token)

        def resources():
            result = gateway("/resources")
            require(result.get("connection_verified") is True and result.get("provider_mode") in {"aws", "contract"})
            require(0 <= time.time() - stamp(result.get("observed_at")) < 120)
            binding = result["binding"]
            require(binding["region"] == "us-east-1" and binding["source_prefix"] == "h02/knowledge/"
                    and binding["embedding_model_id"] == "amazon.titan-embed-text-v2:0"
                    and type(binding["dimensions"]) is int and binding["dimensions"] == 1024)
            for key in ("account_id", "source_bucket", "vector_bucket", "index_arn", "knowledge_base_id", "data_source_id"):
                require(isinstance(binding[key], str) and bool(binding[key]))
            digest(binding["template_digest"])
            ids = result["resource_request_ids"]
            require(isinstance(ids, list) and len(ids) == (4 if result["provider_mode"] == "aws" else 1)
                    and all(isinstance(value, str) and value for value in ids) and len(set(ids)) == len(ids))
            return result

        root = app("/v1/receipts/" + suite_id)
        require(root["practice_id"] == "P02" and root["activity_id"] == "H02"
                and root["contract_version"] == "p02-document-v1" and root["suite_id"] == suite_id
                and root["run_state"] == "finished")
        started, finished = stamp(root["started_at"]), stamp(root["finished_at"])
        require(0 <= finished - started <= 240 and 0 <= time.time() - finished < 600)
        build = app("/v1/build-info")
        require(build == root["build"] == root["final_build"])
        require(build["runner_files"] == self.files and build["runner_digest"] == self.runner_digest
                and build["contract_digest"] == self.contract_digest)
        digest(build["source_digest"])
        rows = root["cases"]
        require(isinstance(rows, list) and len(rows) == len(self.cases))
        require([row["case_id"] for row in rows] == [case["case_id"] for case in self.cases])
        ids = [row["execution_id"] for row in rows]
        require(len(set(ids)) == len(ids) and all(str(UUID(value)) == value for value in ids))
        before = resources()
        results, calls, provider_ids = [], [], set()
        for expected, row in zip(self.cases, rows):
            execution_id = row["execution_id"]
            ledger = gateway("/executions/" + execution_id)
            require(started <= stamp(ledger["started_at"]) <= stamp(ledger["closed_at"]) <= finished)
            source = gateway("/executions/" + execution_id + "/source") if expected["valid"] else None
            case_result = verify_case({**expected, "suite_id": suite_id, "execution_id": execution_id},
                                      row["execution"], ledger, source, source_digest=build["source_digest"],
                                      runner_digest=self.runner_digest, bucket=before["binding"]["source_bucket"],
                                      provider_mode=before["provider_mode"])
            current_ids = case_result.get("provider_request_ids", []) + ([case_result["source_read_request_id"]] if "source_read_request_id" in case_result else [])
            require(not provider_ids.intersection(current_ids))
            provider_ids.update(current_ids)
            results.append({"case_id": expected["case_id"], **case_result})
            calls.append({"case_id": expected["case_id"], "ledger": ledger, "source_requery": source})
        after = resources()
        require(before["binding"] == after["binding"] and before["provider_mode"] == after["provider_mode"])
        require(app("/v1/build-info") == build and app("/v1/receipts/" + suite_id) == root)
        return {"case_contract_verified": True, "provider_mode": before["provider_mode"], "build": build,
                "cases": results, "root": root, "provider_evidence": calls,
                "resource_evidence": {"before": before, "after": after}}
