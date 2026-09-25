"""Real TCP and Presidio from /app in the dedicated P12 image; no NeMo or AWS."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, ProxyHandler, Request
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-client", action="store_true")
    options = parser.parse_args()
    client_calls = []
    client_digest = None
    if options.application_client:
        sys.path.insert(0, "/client")
        from service_client import ServiceClient
        client_digest = hashlib.sha256(Path("/client/service_client.py").read_bytes()).hexdigest()
    assert os.getuid() == 65532
    names = ("privacy_server.py", "privacy.py")
    assert sorted(path.name for path in Path("/app").iterdir()) == sorted(names)
    source = hashlib.sha256()
    file_digests = {}
    for name in names:
        content = (Path("/app") / name).read_bytes()
        file_digests[name] = hashlib.sha256(content).hexdigest()
        source.update(name.encode())
        source.update(content)
    tokens = {role: secrets.token_hex(32) for role in ("control", "service", "verifier")}
    opener = build_opener(ProxyHandler({}))
    with TemporaryDirectory(prefix="p12-privacy-http-") as temporary, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment.update({f"GUIDED_P12_PRIVACY_{role.upper()}_TOKEN": value for role, value in tokens.items()})
        environment["GUIDED_P12_PRIVACY_DATABASE"] = str(Path(temporary) / "ledger.sqlite3")
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "privacy_server:create_app", "--factory",
                                    "--fd", str(listener.fileno()), "--log-level", "warning"],
                                   cwd="/app", env=environment, pass_fds=(listener.fileno(),),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def request(path, role=None, payload=None):
            headers = {"Content-Type": "application/json"}
            if role:
                headers["Authorization"] = "Bearer " + tokens[role]
            req = Request(origin + path, headers=headers,
                          data=json.dumps(payload).encode() if payload is not None else None)
            try:
                with opener.open(req, timeout=5) as response:
                    return response.status, json.load(response)
            except HTTPError as response:
                return response.code, json.load(response)

        try:
            deadline = time.monotonic() + 45
            while True:
                if process.poll() is not None:
                    raise RuntimeError("privacy process exited during startup")
                try:
                    if request("/readyz")[0] == 200:
                        break
                except (URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("privacy readiness")
                time.sleep(.2)
            status, build = request("/v1/build-info", "verifier")
            assert status == 200
            assert build["source_digest"] == build["current_source_digest"] == source.hexdigest()
            assert request("/v1/build-info", "service")[0] == 401
            suite = str(uuid4())
            ids = [str(uuid4()) for _ in range(3)]
            assert request("/v1/suites", "control", {"suite_id": suite, "execution_ids": ids})[0] == 200
            examples = [("계정 복구 절차 안내", "계정 복구 절차 안내"),
                        ("Email: learner@example.com", "Email: <EMAIL_ADDRESS>"),
                        ("Resident number: 900101-1234568", "Resident number: <KR_RRN>")]
            for execution, (text, expected) in zip(ids, examples):
                if options.application_client:
                    application = ServiceClient(suite_id=suite, execution_id=execution,
                        origins={"privacy": origin, "nemo": "http://unused.invalid", "gateway": "http://unused.invalid"},
                        tokens={"privacy": tokens["service"], "nemo": "unused-fixture"},
                        capabilities={role: secrets.token_hex(32) for role in ("input_rail", "retrieval_rail", "output_rail", "main")})
                for stage in ("input_privacy", "output_privacy"):
                    body = {"suite_id": suite, "execution_id": execution, "stage": stage, "text": text}
                    if options.application_client:
                        assert asyncio.run(application.privacy(stage, text)) == expected
                    else:
                        status, response = request("/v1/process", "service", body)
                        assert status == 200 and response["text"] == expected
                        assert response["evidence"]["versions"]["presidio-analyzer"] == "2.2.362"
                        assert response["evidence"]["service_digest"] == source.hexdigest()
                if options.application_client:
                    client_calls.append({"execution_id": execution, "calls": application.calls})
            assert request("/v1/process", "service", body)[0] == 409
            assert request("/v1/process", "verifier", body)[0] == 401
            assert request("/v1/process", "service", {**body, "task_completed": True})[0] == 422
            assert request(f"/v1/suites/{suite}/close", "control", {})[0] == 200
            status, ledger = request(f"/v1/suites/{suite}/ledger", "verifier")
            assert status == 200 and ledger["closed_at"] is not None and len(ledger["calls"]) == 6
            assert all(call["state"] == "completed" for call in ledger["calls"])
            assert ledger["service_digest"] == source.hexdigest()
            assert all(call["evidence"]["service_digest"] == source.hexdigest() for call in ledger["calls"])
            assert all(call["evidence"]["versions"]["presidio-analyzer"] == "2.2.362" for call in ledger["calls"])
            for record in client_calls:
                for call in record["calls"]:
                    provider = next(row for row in ledger["calls"]
                                    if row["execution_id"] == record["execution_id"] and row["stage"] == call["stage"])
                    assert call["state"] == "completed" and call["evidence"] == provider["evidence"]
            assert "learner@example.com" not in json.dumps(ledger)
            assert "900101-1234568" not in json.dumps(ledger)
            assert request(f"/v1/suites/{suite}/ledger", "service")[0] == 401
            print(json.dumps({"scope": "dedicated P12 image, actual TCP/Presidio; no NeMo, grader, Browser or AWS",
                              "uid": os.getuid(), "file_digests": file_digests, "build": build,
                              "application_client": options.application_client, "client_digest": client_digest,
                              "client_calls": client_calls,
                              "cases": 6, "replay_status": 409, "wrong_role_status": 401,
                              "verdict_submission_status": 422, "ledger": ledger}, ensure_ascii=False))
        finally:
            process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    main()
