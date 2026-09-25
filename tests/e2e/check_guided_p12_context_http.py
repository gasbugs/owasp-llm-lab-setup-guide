"""Run inside the packaged Context image: actual TCP and SQLite lexical retrieval."""
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
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4


def main():
    assert os.getuid() == 65532
    names = ("context_server.py", "context_store.py")
    assert sorted(path.name for path in Path("/app").iterdir()) == sorted(names)
    source = hashlib.sha256()
    files = {}
    for name in names:
        content = (Path("/app") / name).read_bytes()
        files[name] = hashlib.sha256(content).hexdigest()
        source.update(name.encode())
        source.update(content)
    tokens = {role: secrets.token_hex(32) for role in ("control", "service", "verifier")}
    opener = build_opener(ProxyHandler({}))
    with TemporaryDirectory(prefix="p12-context-") as temp, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment.update({f"GUIDED_P12_CONTEXT_{role.upper()}_TOKEN": value for role, value in tokens.items()})
        environment["GUIDED_P12_CONTEXT_DATABASE"] = str(Path(temp) / "context.sqlite3")
        child = subprocess.Popen([sys.executable, "-m", "uvicorn", "context_server:create_app", "--factory",
                                  "--fd", str(listener.fileno()), "--log-level", "warning"],
                                 cwd="/app", env=environment, pass_fds=(listener.fileno(),),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def request(path, role="service", body=None):
            req = Request(origin + path, headers={"Authorization": "Bearer " + tokens[role], "Content-Type": "application/json"},
                          data=json.dumps(body).encode() if body is not None else None)
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, json.load(response)
            except HTTPError as response:
                return response.code, json.load(response)

        try:
            deadline = time.monotonic() + 15
            while True:
                assert child.poll() is None, "context service exited"
                try:
                    if request("/readyz")[0] == 200:
                        break
                except (URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("context service startup")
                time.sleep(.1)
            status, build = request("/v1/build-info", "verifier")
            assert status == 200 and build["source_digest"] == build["current_source_digest"] == source.hexdigest()
            suite = str(uuid4())
            ids = [str(uuid4()) for _ in range(6)]
            documents = [{"document_id": "account", "tenant": "team-a", "text": "계정 복구: 지원 담당자에게 문의하세요."},
                         {"document_id": "foreign", "tenant": "team-b", "text": "계정 복구: 다른 팀의 합성 문서."}]
            status, issued = request("/v1/suites", "control", {"suite_id": suite, "execution_ids": ids, "documents": documents})
            assert status == 200

            def stage(index, name, value):
                return request("/v1/stages/" + name, body={"suite_id": suite, "execution_id": ids[index], "value": value})

            for index in (0, 5):
                assert stage(index, "authenticate", issued["credentials"]["reader"])[1]["allowed"] is True
                assert stage(index, "authorize", "team-a")[1]["allowed"] is True
                status, result = stage(index, "retrieval", "계정 복구" if index == 0 else "unmatchedfixture")
                assert status == 200
                assert result["text"] == (documents[0]["text"] if index == 0 else "")
                assert [hit["document_id"] for hit in result["evidence"]["hits"]] == (["account"] if index == 0 else [])
            assert stage(1, "authenticate", issued["credentials"]["visitor"])[1]["allowed"] is True
            assert stage(1, "authorize", "team-a")[1]["allowed"] is False
            assert stage(2, "authenticate", "invalid-fixture-credential")[1]["allowed"] is False
            assert stage(3, "authenticate", issued["credentials"]["reader"])[1]["allowed"] is True
            assert stage(3, "authorize", "team-b")[1]["allowed"] is False
            assert stage(4, "retrieval", "계정 복구")[0] == 403
            assert stage(0, "retrieval", "계정 복구")[0] == 409
            assert request(f"/v1/suites/{suite}/ledger", "service")[0] == 401
            assert request(f"/v1/suites/{suite}/close", "control", {})[0] == 200
            status, ledger = request(f"/v1/suites/{suite}/ledger", "verifier")
            assert status == 200 and ledger["retrieval_count"] == 2 and ledger["closed_at"] is not None
            assert len(ledger["calls"]) == 12
            assert ledger["service_digest"] == source.hexdigest()
            serialized = json.dumps(ledger)
            for value in (*tokens.values(), *issued["credentials"].values(), "invalid-fixture-credential", "계정 복구"):
                assert value not in serialized
            assert stage(1, "retrieval", "계정")[0] == 409
            print(json.dumps({"scope": "packaged Context service, real TCP/SQLite FTS, synthetic identities/corpus; no embeddings, NeMo, AWS or complete P12",
                              "uid": os.getuid(), "file_digests": files, "build": build,
                              "executions": 6, "ledger": ledger}, ensure_ascii=False))
        finally:
            child.terminate()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)


if __name__ == "__main__":
    main()
