"""Trusted P12 lifecycle orchestration; caller owns cases and receipt persistence.

No course verdict, retry, raw credential, or privileged token enters the worker result.
"""
import json
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from execution import execute

SERVICES = ("context", "privacy", "nemo", "gateway")
ROLES = {"input_rail", "retrieval_rail", "output_rail", "main"}


class LifecycleError(RuntimeError):
    def __init__(self, status=None):
        super().__init__("P12 lifecycle request failed")
        self.status = status


class Workflow:
    def __init__(self, origins, tokens, *, transport=None, worker=execute):
        if set(origins) != set(SERVICES) or set(tokens) != set(SERVICES):
            raise ValueError("dedicated service configuration required")
        for service, origin in origins.items():
            parsed = urlsplit(origin)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
                raise ValueError("invalid service origin")
            expected = {"control"} if service == "gateway" else {"control", "service"}
            if set(tokens[service]) != expected:
                raise ValueError("only control and invocation credentials belong in workflow")
            if any(not isinstance(value, str) or not value or not value.isascii() for value in tokens[service].values()):
                raise ValueError("invalid lifecycle credential")
        self.origins = {key: value.rstrip("/") for key, value in origins.items()}
        self.tokens = {key: dict(value) for key, value in tokens.items()}
        self.transport, self.worker = transport, worker

    def _post(self, service, path, body):
        try:
            with httpx.Client(timeout=5, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                with client.stream("POST", self.origins[service] + path, json=body,
                                   headers={"Authorization": "Bearer " + self.tokens[service]["control"]}) as response:
                    if response.status_code != 200:
                        raise LifecycleError(response.status_code)
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 131072:
                            raise ValueError("oversized lifecycle response")
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("suite_id") != body.get("suite_id", path.split("/")[-2]):
                raise ValueError("lifecycle binding mismatch")
            return result
        except LifecycleError:
            raise
        except Exception:
            raise LifecycleError() from None

    def run_case(self, source, *, suite_id, execution_id, documents, identity, tenant, message):
        suite, execution = str(UUID(suite_id)), str(UUID(execution_id))
        if identity not in {"reader", "visitor", "invalid"}:
            raise ValueError("unknown server-owned case identity")
        register = {"suite_id": suite, "execution_ids": [execution]}
        attempts, close_candidates, closures = [], [], {}
        result = {"suite_id": suite, "execution_id": execution, "lifecycle_status": "error",
                  "execution": None, "registration_attempts": attempts, "closures": closures}
        try:
            identities, grants = None, None
            for service in SERVICES:
                attempts.append(service)
                close_candidates.append(service)
                prefix = "/v1/p12" if service == "gateway" else "/v1"
                payload = {**register, "documents": documents} if service == "context" else register
                try:
                    response = self._post(service, prefix + "/suites", payload)
                except LifecycleError as error:
                    if error.status == 409:
                        # A pre-existing suite is not owned by this attempt; do not close it.
                        close_candidates.pop()
                    raise
                if service == "context":
                    identities = response["credentials"]
                    if (set(identities) != {"reader", "visitor"}
                            or any(not isinstance(value, str) or not value or not value.isascii() for value in identities.values())):
                        raise ValueError("invalid issued identity")
                if service == "gateway":
                    issued = response["grants"]
                    if not isinstance(issued, list) or len(issued) != 4:
                        raise ValueError("invalid role grants")
                    grants = {}
                    for item in issued:
                        if item["suite_id"] != suite or item["execution_id"] != execution or item["role"] in grants:
                            raise ValueError("invalid grant binding")
                        value = item["capability"]
                        if not isinstance(value, str) or not value.isascii() or not 40 <= len(value) <= 256:
                            raise ValueError("invalid role credential")
                        grants[item["role"]] = value
                    if set(grants) != ROLES or len(set(grants.values())) != 4:
                        raise ValueError("invalid grant roles")
            configuration = {"suite_id": suite, "execution_id": execution, "origins": self.origins,
                             "tokens": {service: self.tokens[service]["service"] for service in SERVICES if service != "gateway"},
                             "capabilities": grants}
            request = {"credential": identities.get(identity, "invalid-fixture-credential"), "tenant": tenant, "message": message}
            result["execution"] = self.worker(source, request, configuration)
            result["lifecycle_status"] = "finished"
        except Exception:
            # Preserve unknown downstream state; never expose exception text or infer zero calls.
            result["lifecycle_status"] = "error"
        finally:
            for service in close_candidates:
                prefix = "/v1/p12" if service == "gateway" else "/v1"
                try:
                    response = self._post(service, f"{prefix}/suites/{suite}/close", {})
                    stamp = response["closed_at"]
                    if type(stamp) not in {int, float} or not 0 < stamp < float("inf"):
                        raise ValueError("invalid closure")
                    closures[service] = {"state": "closed", "closed_at": stamp}
                except Exception:
                    closures[service] = {"state": "unknown"}
                    result["lifecycle_status"] = "error"
        return result
