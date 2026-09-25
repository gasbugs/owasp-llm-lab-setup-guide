"""Read-only whole-suite P03 evidence collection; no learner code or AWS writes.

Registered resource state is not an IAM/configuration audit. Actual native job
and retrieval responses are separately checked by verify_case. HTTP/API grading
must preserve the reported provider mode rather than calling fixtures AWS proof.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p03_results import EvidenceError, json_digest, require, stamp, verify_case

FILES = ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")
CONTRACT_URI = "s3://p03-contract/h03/knowledge/current-policy.md"


def origin(value):
    parsed = urlsplit(value)
    require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and parsed.path in {"", "/"})
    return value.rstrip("/")


def fixture_status(case, job):
    response = {"provider_mode": "contract"}
    observed = case.get("observed_job", "current")
    if observed == "current":
        response["ingestion_job_id"] = job
    elif observed == "different":
        response["ingestion_job_id"] = "previous-job"
    else:
        require(observed == "missing")
    if "status" in case:
        response["status"] = case["status"]
    elif case["backend"] == "provider":
        response["status"] = "COMPLETE"
    return response


class SuiteVerification:
    def __init__(self, runner_root, app_origin, gateway_origin, app_token, gateway_token, *, transport=None):
        root = Path(runner_root)
        spec = importlib.util.spec_from_file_location("p03_verifier_owned_cases", root / "cases.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.cases = module.cases()
        require(isinstance(self.cases, list) and 1 <= len(self.cases) <= 32)
        self.contract_digest = json_digest(self.cases)
        self.files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}
        self.runner_digest = hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()
        self.app_origin, self.gateway_origin = origin(app_origin), origin(gateway_origin)
        require(all(isinstance(token, str) and token and token.isascii() for token in (app_token, gateway_token)))
        self.app_token, self.gateway_token, self.transport = app_token, gateway_token, transport

    def collect(self, suite_id):
        try:
            require(str(UUID(suite_id)) == suite_id)
            deadline = time.monotonic() + 60
            with httpx.Client(follow_redirects=False, trust_env=False, transport=self.transport) as client:
                def get(base, path, token):
                    remaining = deadline - time.monotonic()
                    require(remaining > 0)
                    with client.stream("GET", base + path, headers={"Authorization": "Bearer " + token},
                                       timeout=min(5, remaining)) as response:
                        require(response.status_code == 200)
                        raw = bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            require(len(raw) <= 1048576 and time.monotonic() < deadline)
                    value = json.loads(raw)
                    require(isinstance(value, dict))
                    return value

                def app(path):
                    return get(self.app_origin, path, self.app_token)

                def gateway(path):
                    return get(self.gateway_origin, "/v1/p03" + path, self.gateway_token)

                root = app("/v1/receipts/" + suite_id)
                require(root["practice_id"] == "P03" and root["activity_id"] == "H03"
                        and root["contract_version"] == "p03-search-v1" and root["suite_id"] == suite_id
                        and root["run_state"] == "finished")
                started, finished = stamp(root["started_at"]), stamp(root["finished_at"])
                require(0 <= finished - started <= 240 and 0 <= time.time() - finished < 600)
                build = app("/v1/build-info")
                require(json_digest(build) == json_digest(root["build"]) == json_digest(root["final_build"]))
                require(build["runner_files"] == self.files and build["runner_digest"] == self.runner_digest
                        and build["contract_digest"] == self.contract_digest)
                require(isinstance(build["source_digest"], str) and re.fullmatch(r"[0-9a-f]{64}", build["source_digest"]))
                rows = root["cases"]
                require(isinstance(rows, list) and len(rows) == len(self.cases))
                require([row["case_id"] for row in rows] == [case["case_id"] for case in self.cases])
                ids = [row["execution_id"] for row in rows]
                require(len(set(ids)) == len(ids) and all(str(UUID(value)) == value for value in ids))
                registration = gateway("/suites/" + suite_id)
                require(registration["practice_id"] == "P03" and registration["activity_id"] == "H03"
                        and registration["contract_version"] == "p03-search-v1" and registration["suite_id"] == suite_id
                        and registration["state"] == "prepared" and registration["contract_digest"] == self.contract_digest)
                prepared = stamp(registration["prepared_at"])
                require(started <= stamp(registration["started_at"]) <= prepared <= finished)
                bindings = registration["cases"]
                require(isinstance(bindings, list) and len(bindings) == len(rows)
                        and [(b["case_id"], b["execution_id"]) for b in bindings] == [(r["case_id"], r["execution_id"]) for r in rows])
                jobs = [b["current_job_id"] for b in bindings]
                require(len(set(jobs)) == len(jobs) and all(isinstance(job, str) and re.fullmatch(r"[A-Za-z0-9-]{1,128}", job) for job in jobs))
                resources = registration["resources"]
                require(set(resources) == {"provider_mode", "binding", "source_uris"}
                        and resources["provider_mode"] in {"aws", "contract"})
                if resources["provider_mode"] == "contract":
                    require(resources["binding"] is None and resources["source_uris"] == [CONTRACT_URI])
                else:
                    binding = resources["binding"]
                    require(binding["region"] == "us-east-1" and isinstance(resources["source_uris"], list)
                            and 1 <= len(resources["source_uris"]) <= 16)
                    prefix = binding["source_uri_prefix"]
                    require(isinstance(prefix, str) and re.fullmatch(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/h03/knowledge/", prefix))
                    require(all(isinstance(uri, str) and uri.startswith(prefix) and uri != prefix for uri in resources["source_uris"]))

                def inspect():
                    observation = gateway("/suites/" + suite_id + "/resources")
                    require(observation["scope"] == "registered-resource-state" and observation["suite_id"] == suite_id
                            and 0 <= time.time() - stamp(observation["observed_at"]) < 120
                            and json_digest(observation["resources"]) == json_digest(resources))
                    return observation

                before = inspect()
                results, evidence, native_ids, observation_ids = [], [], set(), set()
                previous_end = prepared
                for case, row, binding_row in zip(self.cases, rows, bindings):
                    job = binding_row["current_job_id"]
                    expected = {**case, "suite_id": suite_id, "execution_id": row["execution_id"], "current_job_id": job}
                    mode = resources["provider_mode"] if case["backend"] == "provider" else "contract"
                    if mode == "aws":
                        expected.update({key: resources["binding"][key] for key in
                            ("provider_ingestion_job_id", "knowledge_base_id", "data_source_id")})
                        expected["source_uris"] = resources["source_uris"]
                    else:
                        expected.update(status_response=fixture_status(case, job), source_uris=[CONTRACT_URI])
                    ledger = gateway("/executions/" + row["execution_id"])
                    require(previous_end <= stamp(ledger["started_at"]) <= stamp(ledger["closed_at"]) <= finished)
                    previous_end = ledger["closed_at"]
                    checked = verify_case(expected, row["execution"], ledger,
                        source_digest=build["source_digest"], runner_digest=self.runner_digest, now=time.time(), provider_mode=mode)
                    for seen, current in ((native_ids, checked["provider_request_ids"]), (observation_ids, checked["observation_ids"])):
                        require(not seen.intersection(current))
                        seen.update(current)
                    results.append({"case_id": case["case_id"], "provider_mode": mode, **checked})
                    evidence.append(ledger)
                after = inspect()
                require(json_digest(app("/v1/build-info")) == json_digest(build)
                        and json_digest(app("/v1/receipts/" + suite_id)) == json_digest(root)
                        and json_digest(gateway("/suites/" + suite_id)) == json_digest(registration))
            return {"case_contract_verified": True, "provider_mode": resources["provider_mode"],
                    "root": root, "build": build, "cases": results, "registration": registration,
                    "provider_evidence": evidence, "resource_evidence": {"before": before, "after": after}}
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError, httpx.HTTPError):
            raise EvidenceError("P03 suite evidence could not be verified") from None
