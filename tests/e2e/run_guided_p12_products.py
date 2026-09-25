"""Native products over TCP; SDK double or explicitly selected live AWS baseline."""
import hashlib
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4

sys.path.insert(0, "/app/learner")
from workflow import Workflow
from run_server import create_app, configured_app
sys.path.insert(0, "/checks")
from p12_results import EvidenceError
from p12_binding import SCAFFOLD, validate_run_binding
from p12_grading import grade_run
from p12_verification import verify_case_from_services, verified_run_snapshot
from p12_suite import DOCS, CASES, ORDER
import uvicorn

ORIGINS = {name: f"http://{name}:8000" for name in ("context", "privacy", "nemo", "gateway")}
AWS_BASELINE = os.getenv("P12_AWS_BASELINE") == "1"
AWS_POLICY_SUITE = os.getenv("P12_AWS_POLICY_SUITE") == "1"
DOCS = json.loads(os.environ["P12_PUBLISHER_DOCUMENTS"])
CASES = json.loads(os.environ["P12_PUBLISHER_CASES"])


def run_http_suite(workflow, cases, verifier_tokens, starter):
    tokens = {role: os.environ["P12_RUNNER_" + role.upper()] for role in ("control", "verifier")}
    contract_cases = [{"case_id": name, "message": message, "identity": identity, "tenant": "team-a"}
                      for name, message, identity, *_ in cases]
    expected_contract = hashlib.sha256(json.dumps({"cases": contract_cases, "documents": DOCS},
        sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    scaffold = {name: hashlib.sha256((Path("/app/learner") / name).read_bytes()).hexdigest() for name in SCAFFOLD}
    if AWS_POLICY_SUITE:
        environment = {**os.environ, "GUIDED_CONTROL_LAB12_TOKEN": tokens["control"],
                       "GUIDED_VERIFIER_LAB12_TOKEN": tokens["verifier"], "GUIDED_H12_DATABASE": "/tmp/p12-runs.sqlite3",
                       **{f"GUIDED_P12_{service.upper()}_URL": origin for service, origin in ORIGINS.items()}}
        app = configured_app(environment=environment)
    else:
        app = create_app(workflow=workflow, cases=contract_cases,
                         documents=DOCS, tokens=tokens, database="/tmp/p12-runs.sqlite3")
    opener = build_opener(ProxyHandler({}))
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 8000))
        listener.listen(128)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        def request(path, role, body=None):
            req = Request(origin + path, headers={"Authorization": "Bearer " + tokens[role], "Content-Type": "application/json"},
                          data=json.dumps(body).encode() if body is not None else None)
            try:
                with opener.open(req, timeout=600) as response:
                    return response.status, json.load(response)
            except HTTPError as response:
                return response.code, json.load(response)
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.02)
            assert server.started
            suite = str(uuid4())
            assert request("/v1/run", "verifier", {"suite_id": suite})[0] == 401
            assert request("/v1/run", "control", {"suite_id": suite, "task_completed": True})[0] == 422
            status, result = request("/v1/run", "control", {"suite_id": suite})
            assert status == 200 and result["run_state"] == "finished", result
            status, receipt = request(f"/v1/receipts/{suite}", "verifier")
            assert status == 200 and receipt["run_state"] == "finished"
            assert request("/v1/run", "control", {"suite_id": suite})[0] == 409
            assert request(f"/v1/receipts/{suite}", "verifier")[1] == receipt
            status, build_info = request("/v1/build-info", "verifier")
            assert status == 200
            binding = validate_run_binding(receipt, build_info, suite_id=suite,
                case_ids=[case["case_id"] for case in contract_cases], contract_digest=expected_contract,
                scaffold_files=scaffold, now=time.time())
            async def requery():
                checks = []
                async with verified_run_snapshot(origin, tokens["verifier"], suite_id=suite,
                        case_ids=[case["case_id"] for case in contract_cases], contract_digest=expected_contract,
                        scaffold_files=scaffold) as snapshot:
                    assert snapshot["receipt"] == receipt and snapshot["binding"] == binding
                    for case, attempt in zip(cases, snapshot["receipt"]["cases"]):
                        name, _, _, status, stage_count, _ = case
                        try:
                            result = await verify_case_from_services(attempt, ORIGINS, verifier_tokens,
                                expected_case=next(value for value in contract_cases if value["case_id"] == name),
                                source_digest=binding["source_digest"], expected_status=status or 403,
                                expected_stop=None if status == 200 else ORDER[stage_count - 1])
                        except EvidenceError as error:
                            if not starter and status is not None:
                                execution = attempt["lifecycle"]["execution"]
                                diagnostic = {"case": name, "reason": str(error),
                                    "execution_status": execution.get("execution_status"),
                                    "calls": [{key: call.get(key) for key in ("stage", "state", "http_status")}
                                              for call in (execution.get("calls") or [])]}
                                try:
                                    req = Request(ORIGINS["gateway"] + "/v1/p12/suites/" + attempt["suite_id"] + "/ledger",
                                        headers={"Authorization": "Bearer " + verifier_tokens["gateway"]})
                                    with opener.open(req, timeout=5) as response:
                                        ledger = json.loads(response.read(131073))
                                    diagnostic["provider"] = [{"role": grant["role"], "state": grant["state"],
                                        "evidence": {key: (grant.get("evidence") or {}).get(key)
                                            for key in ("classifier_schema_valid", "classifier_answer", "stop_reason", "usage")}}
                                        for grant in ledger["grants"]]
                                except Exception:
                                    diagnostic["provider"] = "ledger diagnostic unavailable"
                                print(json.dumps(diagnostic), file=sys.stderr, flush=True)
                                raise EvidenceError("unexpected product case failure: " + name) from None
                            checks.append({"case_id": name, "evidence_consistent": False})
                        else:
                            assert not starter and status is not None, name
                            checks.append({"case_id": name, "evidence_consistent": result["consistency"]["evidence_consistent"]})
                return {"root_unchanged_after_products": True, "cases": checks}
            requery_result = asyncio.run(requery())
            specifications = [{"input": item, "status": case[3] or 403,
                "stop": None if case[3] == 200 else ORDER[case[4] - 1],
                "input_entities": {"EMAIL_ADDRESS": 1} if case[0] == "input-pii" else {}}
                for item, case in zip(contract_cases, cases)]
            grade = asyncio.run(grade_run(origin, tokens["verifier"], ORIGINS, verifier_tokens,
                suite_id=suite, specifications=specifications, documents=DOCS, scaffold_files=scaffold))
            expected_complete = not AWS_BASELINE and not starter and all(case[3] is not None for case in cases)
            assert grade["task_completed"] is expected_complete, grade
            assert grade["security_verdict"] == ("PASS" if expected_complete else "ERR"), grade
            def remote_grade(body, credential):
                req = Request("http://verifier:8000/v1/verify/p12", data=json.dumps(body).encode(),
                    headers={"Authorization": "Bearer " + credential, "Content-Type": "application/json"})
                try:
                    with opener.open(req, timeout=190) as response:
                        return response.status, json.load(response)
                except HTTPError as response:
                    return response.code, json.load(response)
            credential = os.environ["P12_VERIFIER_CONTROL"]
            assert remote_grade({"suite_id": suite}, "wrong-fixture")[0] == 401
            assert remote_grade({"suite_id": suite, "task_completed": True}, credential)[0] == 422
            status, tcp_grade = remote_grade({"suite_id": suite}, credential)
            assert status == 200 and tcp_grade == grade, tcp_grade
            return receipt, binding, requery_result, grade, tcp_grade
        finally:
            server.should_exit = True
            thread.join(10)
            assert not thread.is_alive()


def main():
    opener = build_opener(ProxyHandler({}))
    tokens = {service: {role: os.environ[f"GUIDED_P12_{service.upper()}_{role.upper()}_TOKEN"]
                       for role in (("control", "verifier") if service == "gateway" else ("control", "service", "verifier"))}
              for service in ORIGINS}

    def request(service, path, role="control", body=None):
        req = Request(ORIGINS[service] + path, headers={"Authorization": "Bearer " + tokens[service][role],
                      "Content-Type": "application/json"}, data=json.dumps(body).encode() if body is not None else None)
        try:
            with opener.open(req, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            return response.code, json.load(response)

    for service in ORIGINS:
        deadline = time.monotonic() + 60
        path = "/v1/p12/suites/00000000-0000-0000-0000-000000000000/ledger" if service == "gateway" else "/readyz"
        while True:
            try:
                status, _ = request(service, path, "verifier")
                if status == (404 if service == "gateway" else 200):
                    break
            except (URLError, TimeoutError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("P12 product readiness: " + service)
            time.sleep(.2)

    cases = list(CASES)
    if os.getenv("P12_WITHOUT_CLASSIFIER_FAULT") == "1":
        cases = [case for case in cases if case[0] != "classifier-error"]
    if AWS_BASELINE:
        cases = [case for case in cases if case[0] == "normal"]
    records = []
    workflow = Workflow(ORIGINS, {service: {role: value for role, value in roles.items() if role != "verifier"}
                                  for service, roles in tokens.items()})
    builds = {}
    for service in ("context", "privacy", "nemo"):
        status, info = request(service, "/v1/build-info", "verifier")
        assert status == 200 and info["source_digest"] == info["current_source_digest"]
        builds[service] = info
    starter = os.getenv("P12_CHECK_STARTER") == "1"
    receipt, run_binding, root_requery, grade, tcp_grade = run_http_suite(workflow, cases,
        {service: values["verifier"] for service, values in tokens.items()}, starter)
    assert len(receipt["cases"]) == len(cases)
    for (name, message, identity, expected_status, stage_count, retrieval_count), attempt in zip(cases, receipt["cases"]):
        assert attempt["case_id"] == name
        suite, execution = attempt["suite_id"], attempt["execution_id"]
        lifecycle = attempt["lifecycle"]
        assert lifecycle["lifecycle_status"] == "finished", lifecycle
        assert set(lifecycle["closures"]) == set(ORIGINS)
        result = lifecycle["execution"]
        ledgers = {}
        for service in ORIGINS:
            prefix = "/v1/p12" if service == "gateway" else "/v1"
            status, ledger = request(service, f"{prefix}/suites/{suite}/ledger", "verifier")
            assert status == 200 and ledger["closed" if service == "gateway" else "closed_at"] is not None
            assert ledger["closed" if service == "gateway" else "closed_at"] == lifecycle["closures"][service]["closed_at"]
            ledgers[service] = ledger
        calls = result["calls"]
        if starter:
            assert result["execution_status"] == "not_implemented" and calls == []
            assert all(ledgers[service]["calls"] == [] for service in ("context", "privacy", "nemo"))
            assert all(grant["state"] == "closed_unused" for grant in ledgers["gateway"]["grants"])
            assert ledgers["context"]["retrieval_count"] == 0
        else:
            assert result["execution_status"] == ("service_error" if expected_status is None else "returned"), (name, result)
            if expected_status is not None:
                assert result["result"]["status"] == expected_status, (name, result)
            assert [call["stage"] for call in calls] == ORDER[:stage_count], (name, calls)
            assert ledgers["context"]["retrieval_count"] == retrieval_count
            rows = {row["stage"]: row for service in ("context", "privacy", "nemo") for row in ledgers[service]["calls"]}
            gateway = {row["role"]: row for row in ledgers["gateway"]["grants"]}
            assert set(rows) == set(ORDER[:stage_count]) - {"main"}
            for call in calls:
                stage = call["stage"]
                if stage == "main":
                    evidence = call["evidence"]
                    assert evidence["request_digest"] == gateway[stage]["request_digest"]
                    assert evidence["response_digest"] == gateway[stage]["evidence"]["response_digest"]
                else:
                    row = rows[stage]
                    assert row["input_digest"] == call["input_digest"]
                    if call["state"] == "error":
                        assert row["state"] == "error" and row["evidence"] is None
                        continue
                    for key, value in call["evidence"].items():
                        assert row["evidence"][key] == value, (name, stage, key)
                    service = "nemo" if stage.endswith("_rail") else "privacy" if stage.endswith("_privacy") else "context"
                    assert row["evidence"]["service_digest"] == builds[service]["source_digest"]
                    if stage.endswith("_rail"):
                        assert row["evidence"]["gateway"]["provider_request_id"] == gateway[stage]["evidence"]["provider_request_id"]
            for role, grant in gateway.items():
                assert (grant["state"] != "closed_unused") == (role in ORDER[:stage_count]), (name, role)
            if "input_rail" in rows:
                assert rows["input_privacy"]["evidence"]["output_digest"] == rows["input_rail"]["input_digest"]
            if "retrieval" in rows:
                assert rows["retrieval"]["input_digest"] == rows["input_privacy"]["evidence"]["output_digest"]
            if "retrieval_rail" in rows:
                assert rows["retrieval"]["evidence"]["output_digest"] == rows["retrieval_rail"]["input_digest"]
            if "main" in ORDER[:stage_count]:
                question = message.replace("learner@example.com", "<EMAIL_ADDRESS>")
                hits = rows["retrieval"]["evidence"]["hits"]
                documents = {doc["document_id"]: doc["text"] for doc in DOCS}
                context = "\n\n".join(documents[hit["document_id"]] for hit in hits)
                main_call = next(call for call in calls if call["stage"] == "main")
                binding = gateway["main"]["evidence"]["main_input"]
                assert binding["schema_valid"] is True and binding["prompt_digest"] == main_call["input_digest"]
                assert binding["question_digest"] == hashlib.sha256(question.encode()).hexdigest()
                assert binding["context_digest"] == hashlib.sha256(context.encode()).hexdigest()
            if "output_rail" in rows:
                assert gateway["main"]["evidence"]["response_digest"] == rows["output_rail"]["input_digest"]
            if "output_privacy" in rows:
                assert rows["output_privacy"]["input_digest"] == gateway["main"]["evidence"]["response_digest"]
                assert result["result"]["text_digest"] == rows["output_privacy"]["evidence"]["output_digest"]
                if not (AWS_BASELINE or AWS_POLICY_SUITE):
                    assert rows["output_privacy"]["evidence"]["entity_counts"] == {"EMAIL_ADDRESS": 1}
            if name == "input-pii":
                assert rows["input_privacy"]["evidence"]["entity_counts"] == {"EMAIL_ADDRESS": 1}
        try:
            verified = asyncio.run(verify_case_from_services(attempt, ORIGINS,
                {service: values["verifier"] for service, values in tokens.items()},
                expected_case={"case_id": name, "identity": identity, "tenant": "team-a", "message": message},
                source_digest=receipt["build"]["files"]["pipeline.py"], expected_status=expected_status or 403,
                expected_stop=None if expected_status == 200 else ORDER[stage_count - 1]))
            assert verified["ledgers"] == ledgers and verified["service_builds"] == builds
            consistency = verified["consistency"]
        except EvidenceError:
            assert starter or expected_status is None, name
            consistency = {"evidence_consistent": False}
        else:
            assert not starter and expected_status is not None, name
        record = {"case": name, "execution": result, "ledgers": ledgers, "consistency": consistency,
                  "lifecycle": {key: value for key, value in lifecycle.items() if key != "execution"}}
        serialized = json.dumps(record, ensure_ascii=False)
        for value in ("invalid-fixture-credential", "learner@example.com", *(value for roles in tokens.values() for value in roles.values())):
            assert value not in serialized
        records.append(record)
    for service, info in builds.items():
        status, current = request(service, "/v1/build-info", "verifier")
        assert status == 200 and current == info
    scope = ("live AWS normal-only baseline; actual native rails and Main; no full-task completion/Browser/production deployment"
             if AWS_BASELINE else "separate runner/products/verifier over TCP; actual Presidio/NeMo/SQLite; publisher-injected contract and SDK double; no AWS/Browser/production deployment")
    if AWS_POLICY_SUITE:
        scope = "live AWS server-owned policy suite; actual native rails/Main, synthetic SQLite retrieval; no Browser/production deployment"
    print(json.dumps({"scope": scope,
                      "starter": starter, "cases": len(records), "records": records, "service_builds": builds, "runner_receipt": receipt,
                      "run_binding": run_binding,
                      "root_requery": root_requery,
                      "grade": grade,
                      "tcp_grade": tcp_grade,
                      "artifacts": {name: hashlib.sha256((Path("/app/learner") / name).read_bytes()).hexdigest()
                                    for name in ("pipeline.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "Containerfile")}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
