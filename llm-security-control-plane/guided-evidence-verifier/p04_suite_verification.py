"""Authenticated GET-only P04 evidence collection with bounded continuity checks."""
import json
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p04_results import EvidenceError, require, sha, timestamp, verify_policy_audit, verify_execution_binding
from p04_product import verify_product_response
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

    def collect_case(self, suite_id, index):
        try:
            require(str(UUID(suite_id)) == suite_id and type(index) is int and 0 <= index < len(self.cases))
            with httpx.Client(timeout=15,follow_redirects=False,trust_env=False,transport=self.transport) as client:
                def get(origin,path,token):
                    with client.stream("GET",origin+path,headers={"Authorization":"Bearer "+token}) as response:
                        require(response.status_code == 200)
                        raw=bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk);require(len(raw)<=2097152)
                    return json.loads(raw)
                root=get(self.app_origin,"/v1/receipts/"+suite_id,self.app_token)
                build=get(self.app_origin,"/v1/build-info",self.app_token)
                registration=get(self.gateway_origin,"/v1/p04/suites/"+suite_id,self.gateway_token)
                require(root["suite_id"]==registration["suite_id"]==suite_id and root["practice_id"]==registration["practice_id"]=="P04")
                require(root["run_state"]=="running" and registration["state"]=="prepared")
                require(sha(build)==sha(root["build"]) and build["runner_files"]==self.contract.files
                        and build["runner_digest"]==self.contract.runner_digest
                        and build["contract_digest"]==registration["contract_digest"]==self.contract.contract_digest)
                rows=root["cases"]
                require(len(rows)==len(self.cases)==len(registration["cases"]))
                require([row["case_id"] for row in rows]==[case["case_id"] for case in self.cases])
                require(registration["cases"]==[{key:row[key] for key in ("case_id","execution_id")} for row in rows])
                require(all(row["execution"] is not None for row in rows[:index+1])
                        and all(row["execution"] is None for row in rows[index+1:]))
                row=rows[index];case=self.cases[index]
                path="/v1/p04/executions/"+row["execution_id"]
                record=get(self.gateway_origin,path,self.gateway_token)
                require(timestamp(root["started_at"])<=timestamp(registration["started_at"])<=timestamp(registration["prepared_at"])<=timestamp(record["started_at"]))
                if index:
                    require(timestamp(rows[index-1]["execution"]["closure"]["closed_at"])<=timestamp(record["started_at"]))
                checked=verify_execution_binding(case,row["execution"],record,suite_id=suite_id,
                    execution_id=row["execution_id"],source_digest=build["source_digest"],runner_digest=self.contract.runner_digest,
                    resources=registration["resources"],now=time.time())
                if case["backend"]=="provider":
                    verify_product_response(case,checked["response"],registration["resources"]["guardrail"])
                require(sha(get(self.gateway_origin,path,self.gateway_token))==sha(record)
                        and sha(get(self.app_origin,"/v1/build-info",self.app_token))==sha(build)
                        and sha(get(self.app_origin,"/v1/receipts/"+suite_id,self.app_token))==sha(root))
            return {"suite_id":suite_id,"index":index,"case_id":case["case_id"],"status":"PASS",
                    "case_verified":True,"reason":"실행 코드·호출 기록·정책 결과 대조 완료",
                    "input":case["body"],"expected":case["expected"],"actual":row["execution"]["execution"]["execution_status"]}
        except (KeyError,TypeError,ValueError,AttributeError,OverflowError,RecursionError,httpx.HTTPError):
            error=EvidenceError("케이스 실행 결과 또는 호출·정책 기록이 기대 동작과 다릅니다.")
            case=self.cases[index] if type(index) is int and 0<=index<len(self.cases) else {}
            execution=locals().get("row",{}).get("execution") or {}
            error.details={"input":case.get("body"),"expected":case.get("expected"),
                           "actual":(execution.get("execution") or {}).get("execution_status","실행 기록 확인 실패")}
            raise error from None

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
