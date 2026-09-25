"""GET-only P04 execution collection; product effectiveness and suite grading are separate."""
import json
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p04_results import EvidenceError, require, sha, verify_execution_binding


class ExecutionVerification:
    def __init__(self, origin, token, *, transport=None):
        parsed = urlsplit(origin)
        require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in {"", "/"})
        require(isinstance(token, str) and len(token) >= 32 and token.isascii())
        self.origin, self.token, self.transport = origin.rstrip("/"), token, transport

    def collect(self, case, receipt, *, suite_id, execution_id, source_digest, runner_digest, resources):
        try:
            require(str(UUID(execution_id)) == execution_id)
            deadline = time.monotonic() + 12
            url = self.origin + "/v1/p04/executions/" + execution_id
            with httpx.Client(timeout=5, follow_redirects=False, trust_env=False,
                              transport=self.transport) as client:
                def read():
                    require(time.monotonic() < deadline)
                    with client.stream("GET", url, headers={"Authorization": "Bearer " + self.token}) as response:
                        require(response.status_code == 200)
                        raw = bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            require(len(raw) <= 131072 and time.monotonic() < deadline)
                    value = json.loads(raw)
                    require(isinstance(value, dict))
                    return value

                record = read()
                result = verify_execution_binding(case, receipt, record, suite_id=suite_id,
                    execution_id=execution_id, source_digest=source_digest, runner_digest=runner_digest,
                    resources=resources, now=time.time())
                require(sha(read()) == sha(record))
            return {"binding_result": result, "provider_evidence": record}
        except (EvidenceError, httpx.HTTPError, KeyError, TypeError, ValueError, AttributeError):
            raise EvidenceError("P04 execution evidence could not be verified") from None
