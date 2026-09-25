"""Authenticated GET-only P04 evidence collection with bounded continuity checks."""
import json
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p04_results import EvidenceError, require, sha, timestamp, verify_policy_audit
from p04_suite_results import SuiteContract


def origin(value):
    parsed = urlsplit(value)
    require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
            and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in ("", "/"))
    return value.rstrip("/")


class SuiteVerification:
    def __init__(self, runner_root, app_origin, gateway_origin, app_token, gateway_token, *, transport=None):
        self.contract = SuiteContract(runner_root)
        self.cases = self.contract.cases
        self.app_origin, self.gateway_origin = origin(app_origin), origin(gateway_origin)
        require(all(isinstance(token, str) and token.isascii() and len(token) >= 32
                    for token in (app_token, gateway_token)))
        self.app_token, self.gateway_token, self.transport = app_token, gateway_token, transport

    def collect(self, suite_id):
        try:
            require(str(UUID(suite_id)) == suite_id)
            deadline = time.monotonic() + 60
            with httpx.Client(follow_redirects=False, trust_env=False, transport=self.transport) as client:
                def get(base, path, token, limit=131072, request_timeout=5):
                    remaining = deadline - time.monotonic()
                    require(remaining > 0)
                    with client.stream("GET", base + path, headers={"Authorization": "Bearer " + token},
                                       timeout=min(request_timeout, remaining)) as response:
                        require(response.status_code == 200)
                        raw = bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            require(len(raw) <= limit and time.monotonic() < deadline)
                    result = json.loads(raw)
                    require(isinstance(result, dict))
                    return result

                def app(path):
                    return get(self.app_origin, path, self.app_token, 2097152)

                def gateway(path, request_timeout=5):
                    return get(self.gateway_origin, "/v1/p04" + path, self.gateway_token,
                               request_timeout=request_timeout)

                root = app("/v1/receipts/" + suite_id)
                build = app("/v1/build-info")
                registration = gateway("/suites/" + suite_id)
                rows = root["cases"]
                require(isinstance(rows, list) and len(rows) == len(self.cases))
                ids = [row["execution_id"] for row in rows]
                require(len(set(ids)) == len(ids) and all(str(UUID(value)) == value for value in ids))

                audit_ids = set()

                def inspect():
                    result = gateway("/suites/" + suite_id + "/resources", request_timeout=15)
                    require(result["suite_id"] == suite_id and result["scope"] == "registered-resource-state"
                            and 0 <= time.time() - timestamp(result["observed_at"]) < 120
                            and sha(result["resources"]) == sha(registration["resources"]))
                    if result['resources']['provider_mode'] == 'aws':
                        ids = verify_policy_audit(result['aws_policy_audit'], result['resources'],
                            earliest=result['observed_at'], latest=time.time())
                        require(not audit_ids.intersection(ids))
                        audit_ids.update(ids)
                    return result

                before = inspect()
                records = [gateway("/executions/" + value) for value in ids]
                checked = self.contract.verify(suite_id, root, registration, build, records,
                                               before["resources"], now=time.time())
                for case in checked['cases']:
                    request_ids = case['binding'].get('policy_audit_request_ids', [])
                    native = case['binding']['provider_request_id']
                    if native is not None:
                        request_ids = request_ids + [native]
                    require(not audit_ids.intersection(request_ids))
                    audit_ids.update(request_ids)
                # Every closed record is re-fetched, not just the root's completion flag.
                for value, record in zip(ids, records):
                    require(sha(gateway("/executions/" + value)) == sha(record))
                after = inspect()
                require(sha(app("/v1/build-info")) == sha(build)
                        and sha(app("/v1/receipts/" + suite_id)) == sha(root)
                        and sha(gateway("/suites/" + suite_id)) == sha(registration))
                require(time.monotonic() < deadline)
                # Recheck age after all network reads; an expired result is not cached success.
                checked = self.contract.verify(suite_id, root, registration, build, records,
                                               after["resources"], now=time.time())
            return {**checked, "root": root, "build": build, "registration": registration,
                    "provider_evidence": records, "resource_evidence": {"before": before, "after": after}}
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError, httpx.HTTPError):
            raise EvidenceError("P04 suite evidence could not be collected consistently") from None
