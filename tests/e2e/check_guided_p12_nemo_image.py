"""Check packaged /app code and real factory startup, without a Gateway or AWS."""
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
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4


def main():
    paths = sorted(Path("/app").iterdir())
    assert {path.name for path in paths} == {"nemo.py", "nemo_server.py", "retrieval.py", "gateway_model.py"}
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    opener = build_opener(ProxyHandler({}))
    tokens = {role: secrets.token_hex(32) for role in ("control", "service", "verifier")}
    with TemporaryDirectory(prefix="p12-image-") as temp, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        env.update({f"GUIDED_P12_NEMO_{role.upper()}_TOKEN": value for role, value in tokens.items()})
        env.update(GUIDED_P12_NEMO_DATABASE=str(Path(temp) / "ledger.sqlite3"),
                   GUIDED_P12_GATEWAY_URL="http://127.0.0.1:9")
        process = subprocess.Popen([sys.executable, "-B", "-m", "uvicorn", "nemo_server:create_service", "--factory",
                                    "--fd", str(listener.fileno()), "--log-level", "warning"], cwd="/app",
                                   env=env, pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        def request(path, role=None, body=None):
            headers = {"Content-Type": "application/json"}
            if role:
                headers["Authorization"] = "Bearer " + tokens[role]
            req = Request(origin + path, headers=headers, data=json.dumps(body).encode() if body is not None else None)
            with opener.open(req, timeout=5) as response:
                assert response.status == 200
                return json.load(response)
        try:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "packaged service exited"
                try:
                    ready = request("/readyz")
                    break
                except (OSError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("packaged readiness")
                    time.sleep(.1)
            suite = str(uuid4())
            request("/v1/suites", "control", {"suite_id": suite, "execution_ids": [str(uuid4())]})
            request(f"/v1/suites/{suite}/close", "control", {})
            ledger = request(f"/v1/suites/{suite}/ledger", "verifier")
            assert ledger["closed_at"] is not None and ledger["calls"] == []
            build = request("/v1/build-info", "verifier")
            assert build["source_digest"] == build["current_source_digest"]
            print(json.dumps({"scope": "packaged NeMo service startup and empty closed ledger; no model/Gateway/AWS calls",
                              "uid": os.getuid(), "files": hashes, "ready": ready, "build": build, "ledger": ledger}))
        finally:
            process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    main()
