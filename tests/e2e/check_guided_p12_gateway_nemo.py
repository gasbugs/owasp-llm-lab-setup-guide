"""Two real TCP services plus native NeMo; explicit SDK fixture, never live AWS."""
import argparse
import asyncio
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4
from unittest.mock import patch

import uvicorn

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane"
sys.path.insert(0, str(ROOT / "guided-bedrock-gateway"))
sys.path.insert(0, str(ROOT / "guided-labs/h12-protected-services"))
sys.path.insert(0, str(ROOT / "guided-labs/h12-application-pipeline"))
from p12_capabilities import CapabilityStore
from p12_gateway import create_app as gateway_app
from nemo_server import create_service
from gateway_model import GatewayModel
from service_client import ServiceClient, ServiceError


@contextmanager
def serve(app):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.05)
            assert server.started, "test server did not start"
            yield f"http://127.0.0.1:{listener.getsockname()[1]}"
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "test server failed to stop"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-client", action="store_true")
    options = parser.parse_args()
    opener = build_opener(ProxyHandler({}))
    calls = []
    answer = ["No"]
    def converse(**request):
        calls.append(request)
        if answer[0] == "raise":
            raise RuntimeError("synthetic-sdk-private-error")
        return {"ResponseMetadata": {"RequestId": str(uuid4())}, "output": {"message": {
            "role": "assistant", "content": [{"text": answer[0]}]}}, "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 1, "totalTokens": 11}}

    def request(origin, path, token, body=None):
        req = Request(origin + path, headers={"Authorization": "Bearer " + token,
                      "Content-Type": "application/json"}, data=json.dumps(body).encode() if body is not None else None)
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            return response.code, json.load(response)

    records = []
    with TemporaryDirectory(prefix="p12-gateway-nemo-") as temp:
        store = CapabilityStore(Path(temp) / "gateway.sqlite3")
        gateway = gateway_app(store=store, client=SimpleNamespace(converse=converse),
                              control_token="gateway-control-fixture", verifier_token="gateway-verifier-fixture")
        tokens = {role: "nemo-fixture-" + role for role in ("control", "service", "verifier")}
        with serve(gateway) as gateway_url:
            environment = {f"GUIDED_P12_NEMO_{role.upper()}_TOKEN": value for role, value in tokens.items()}
            environment.update(GUIDED_P12_GATEWAY_URL=gateway_url,
                               GUIDED_P12_NEMO_DATABASE=str(Path(temp) / "nemo.sqlite3"))
            with patch.dict(os.environ, environment):
                nemo = create_service()
            with serve(nemo) as nemo_url:
                for classifier in ("No", "Yes", "Yes\n", "raise"):
                    answer[0] = classifier
                    suite, execution = str(uuid4()), str(uuid4())
                    registration = {"suite_id": suite, "execution_ids": [execution]}
                    status, issued = request(gateway_url, "/v1/p12/suites", "gateway-control-fixture", registration)
                    assert status == 200
                    grants = {grant["role"]: grant for grant in issued["grants"]}
                    assert request(nemo_url, "/v1/suites", tokens["control"], registration)[0] == 200
                    application = ServiceClient(suite_id=suite, execution_id=execution,
                        origins={"privacy": "http://unused.invalid", "nemo": nemo_url, "gateway": gateway_url},
                        tokens={"privacy": "unused-fixture", "nemo": tokens["service"]},
                        capabilities={role: grant["capability"] for role, grant in grants.items()})
                    start = len(calls)
                    for stage in ("input_rail", "retrieval_rail", "output_rail"):
                        body = {"suite_id": suite, "execution_id": execution, "stage": stage,
                                "text": "교육용 문서와 요청", "capability": grants[stage]["capability"]}
                        if options.application_client:
                            try:
                                allowed = asyncio.run(application.rail(stage, body["text"]))
                            except ServiceError:
                                assert classifier not in {"No", "Yes"}
                                assert application.calls[-1]["state"] == "error"
                                assert "allowed" not in application.calls[-1]
                            else:
                                assert classifier in {"No", "Yes"} and allowed == (classifier == "No")
                        else:
                            status, result = request(nemo_url, "/v1/process", tokens["service"], body)
                            if classifier in {"No", "Yes"}:
                                assert status == 200 and result["allowed"] == (classifier == "No"), (status, result)
                                assert result["evidence"]["llm_call"]["model"] == grants[stage]["model"]
                            else:
                                assert status == 503 and result == {"detail": "rail processing failed"}
                        assert request(nemo_url, "/v1/process", tokens["service"], body)[0] == 409
                    assert len(calls) - start == 3
                    assert all(call["inferenceConfig"]["maxTokens"] == 3 for call in calls[start:])
                    if classifier == "No":
                        answer[0] = "교육용 Main 답변"
                        if options.application_client:
                            output = asyncio.run(application.main("계정 복구 안내"))
                        else:
                            main_model = GatewayModel(gateway_url, suite, execution, "main", grants["main"]["capability"])
                            output = asyncio.run(main_model.generate_async("계정 복구 안내", max_tokens=128, temperature=0.0)).content
                        assert output == answer[0] and calls[-1]["inferenceConfig"]["maxTokens"] == 128
                    assert request(nemo_url, f"/v1/suites/{suite}/close", tokens["control"], {})[0] == 200
                    assert request(gateway_url, f"/v1/p12/suites/{suite}/close", "gateway-control-fixture", {})[0] == 200
                    status, rails = request(nemo_url, f"/v1/suites/{suite}/ledger", tokens["verifier"])
                    assert status == 200
                    status, ledger = request(gateway_url, f"/v1/p12/suites/{suite}/ledger", "gateway-verifier-fixture")
                    assert status == 200
                    by_role = {grant["role"]: grant for grant in ledger["grants"]}
                    if options.application_client and classifier == "No":
                        main_evidence = application.calls[-1]["evidence"]
                        assert main_evidence["provider_request_id"] == by_role["main"]["evidence"]["provider_request_id"]
                        assert main_evidence["request_digest"] == by_role["main"]["request_digest"]
                        assert main_evidence["response_digest"] == by_role["main"]["evidence"]["response_digest"]
                        assert main_evidence["capability_digest"] == by_role["main"]["token_digest"]
                    for call in rails["calls"]:
                        grant = by_role[call["stage"]]
                        if classifier in {"No", "Yes"}:
                            assert call["evidence"]["llm_call"]["model"] == grants[call["stage"]]["model"]
                            binding = call["evidence"]["gateway"]
                            assert binding["provider_request_id"] == grant["evidence"]["provider_request_id"]
                            assert binding["capability_digest"] == grant["token_digest"]
                            assert binding["request_digest"] == grant["request_digest"]
                            assert binding["response_digest"] == grant["evidence"]["response_digest"]
                            if options.application_client:
                                client_call = next(row for row in application.calls if row["stage"] == call["stage"])
                                assert client_call["evidence"]["gateway"] == binding
                                assert client_call["input_digest"] == call["input_digest"]
                        else:
                            assert call["state"] == "error" and call["evidence"] is None
                    serialized = json.dumps({"nemo": rails, "gateway": ledger, "client_calls": application.calls})
                    for grant in grants.values():
                        assert grant["capability"] not in serialized
                    assert "교육용 문서와 요청" not in serialized and "synthetic-sdk-private-error" not in serialized
                    records.append({"classifier_fixture": classifier, "nemo": rails, "gateway": ledger,
                                    "client_calls": application.calls})
    print(json.dumps({"scope": "actual NeMo and two TCP services; SDK fixture, no AWS/Browser/full P12 pipeline",
                      "application_client": options.application_client,
                      "client_digest": hashlib.sha256((ROOT / "guided-labs/h12-application-pipeline/service_client.py").read_bytes()).hexdigest(),
                      "suites": len(records), "sdk_calls": len(calls), "records": records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
