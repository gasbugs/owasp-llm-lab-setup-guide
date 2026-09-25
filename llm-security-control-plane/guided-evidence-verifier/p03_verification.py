"""Bounded GET-only P03 case collection; full suite/build validation is separate."""
import json
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p03_results import EvidenceError, json_digest, require, verify_case


class CaseVerification:
    def __init__(self, origin, token, *, transport=None):
        parsed = urlsplit(origin)
        require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in {"", "/"})
        require(isinstance(token, str) and bool(token) and token.isascii())
        self.origin, self.token, self.transport = origin.rstrip("/"), token, transport

    def collect(self, expected, execution, *, source_digest, runner_digest, provider_mode):
        try:
            execution_id = expected["execution_id"]
            require(str(UUID(execution_id)) == execution_id)
            deadline = time.monotonic() + 12
            url = self.origin + "/v1/p03/executions/" + execution_id
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

                ledger = read()
                result = verify_case(expected, execution, ledger, source_digest=source_digest,
                                     runner_digest=runner_digest, now=time.time(), provider_mode=provider_mode)
                require(json_digest(read()) == json_digest(ledger))
            return {"case_result": result, "provider_evidence": ledger}
        except (EvidenceError, httpx.HTTPError, KeyError, TypeError, ValueError, AttributeError):
            raise EvidenceError("P03 case evidence could not be verified") from None
