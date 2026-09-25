"""Trusted P03 lifecycle. Records execution but never decides course completion."""
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from execution import execute


class LifecycleError(RuntimeError):
    def __init__(self, status=None):
        super().__init__("P03 lifecycle request failed")
        self.status = status


class Workflow:
    def __init__(self, origin, control_token, *, transport=None, worker=execute):
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            raise ValueError("invalid configured gateway")
        if not isinstance(control_token, str) or not control_token or not control_token.isascii():
            raise ValueError("invalid lifecycle credential")
        self.origin, self.control_token = origin.rstrip("/"), control_token
        self.transport, self.worker = transport, worker

    def _post(self, path, body, *, timeout=5):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                with client.stream("POST", self.origin + "/v1/p03" + path, json=body,
                                   headers={"Authorization": "Bearer " + self.control_token}) as response:
                    if response.status_code != 200:
                        raise LifecycleError(response.status_code)
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 65536:
                            raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except LifecycleError:
            raise
        except Exception:
            raise LifecycleError() from None

    def prepare_suite(self, *, suite_id, executions, timeout=30):
        if str(UUID(suite_id)) != suite_id or type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ValueError("invalid suite preparation")
        if not isinstance(executions, list) or not 1 <= len(executions) <= 32:
            raise ValueError("bounded execution mapping required")
        ids, names = set(), set()
        for row in executions:
            if (set(row) != {"case_id", "execution_id"} or str(UUID(row["execution_id"])) != row["execution_id"]
                    or not isinstance(row["case_id"], str) or not row["case_id"] or len(row["case_id"]) > 64
                    or not row["case_id"].isascii() or row["execution_id"] in ids or row["case_id"] in names):
                raise ValueError("invalid execution mapping")
            ids.add(row["execution_id"])
            names.add(row["case_id"])
        mapping_digest = hashlib.sha256(json.dumps(executions, sort_keys=True).encode()).hexdigest()
        response = self._post("/suites", {"suite_id": suite_id, "executions": executions}, timeout=timeout)
        if response.get("prepared") is not True or response != {"suite_id": suite_id, "contract_version": "p03-search-v1",
                        "mapping_digest": mapping_digest, "prepared": True}:
            raise LifecycleError()

    def run_case(self, source_path, *, suite_id, execution_id, runner_digest, timeout=75):
        if str(UUID(suite_id)) != suite_id or str(UUID(execution_id)) != execution_id:
            raise ValueError("server-issued UUIDs required")
        with Path(source_path).open("rb") as stream:
            source = stream.read(65537)
        if len(source) > 65536:
            raise ValueError("source limit")
        source_digest = hashlib.sha256(source).hexdigest()
        result = {"suite_id": suite_id, "execution_id": execution_id, "source_digest": source_digest,
                  "runner_digest": runner_digest, "lifecycle_status": "error", "execution": None,
                  "closure": {"state": "unknown"}}
        close_candidate = True
        try:
            try:
                grant = self._post("/executions", {"suite_id": suite_id, "execution_id": execution_id,
                                   "source_digest": source_digest, "runner_digest": runner_digest})
            except LifecycleError as error:
                if error.status == 409:
                    close_candidate = False
                raise
            if (grant.get("suite_id") != suite_id or grant.get("execution_id") != execution_id
                    or grant.get("practice_id") != "P03" or grant.get("activity_id") != "H03"
                    or grant.get("contract_version") != "p03-search-v1"):
                raise ValueError("invalid issued identity")
            stamp, capability = grant["started_at"], grant["capability"]
            if (type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0
                    or not isinstance(capability, str) or not capability.isascii() or not 40 <= len(capability) <= 256):
                raise ValueError("invalid issued execution")
            result["started_at"] = stamp
            configuration = {"suite_id": suite_id, "execution_id": execution_id,
                             "origin": self.origin, "capability": capability}
            execution = self.worker(source_path, grant["current_job_id"], configuration, timeout=timeout)
            result["execution"] = execution
            if execution.get("source_digest") != source_digest:
                raise ValueError("source changed during execution")
            result["lifecycle_status"] = "finished"
        except Exception:
            result["lifecycle_status"] = "error"
        finally:
            if close_candidate:
                try:
                    closure = self._post(f"/executions/{execution_id}/close", {})
                    stamp = closure.get("closed_at")
                    if (closure.get("execution_id") != execution_id or type(stamp) not in (int, float)
                            or not math.isfinite(stamp) or stamp <= 0 or stamp < result.get("started_at", 0)):
                        raise ValueError("invalid closure")
                    result["closure"] = {"state": "closed", "closed_at": stamp}
                except Exception:
                    result["lifecycle_status"] = "error"
        return result
