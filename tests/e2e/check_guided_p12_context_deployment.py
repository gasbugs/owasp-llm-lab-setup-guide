"""Selected production Compose service, dedicated volume, recreate persistence."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
SERVICE = "guided-p12-context"
PROBE = '''
import json, os, sys
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4
opener = build_opener(ProxyHandler({}))
def call(path, role, body=None):
    req = Request("http://127.0.0.1:8000" + path,
        headers={"Authorization": "Bearer " + os.environ["GUIDED_P12_CONTEXT_" + role + "_TOKEN"],
                 "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None)
    with opener.open(req, timeout=5) as response:
        assert response.status == 200
        return json.load(response)
if len(sys.argv) > 1:
    suite = sys.argv[1]
else:
    suite, execution = str(uuid4()), str(uuid4())
    issued = call("/v1/suites", "CONTROL", {"suite_id": suite, "execution_ids": [execution],
        "documents": [{"document_id": "account", "tenant": "team-a", "text": "계정 복구"}]})
    def stage(name, value):
        return call("/v1/stages/" + name, "SERVICE",
            {"suite_id": suite, "execution_id": execution, "value": value})
    assert stage("authenticate", issued["credentials"]["reader"])["allowed"] is True
    assert stage("authorize", "team-a")["allowed"] is True
    assert stage("retrieval", "계정")["text"] == "계정 복구"
    call("/v1/suites/" + suite + "/close", "CONTROL", {})
ledger = call("/v1/suites/" + suite + "/ledger", "VERIFIER")
assert ledger["closed_at"] is not None and ledger["retrieval_count"] == 1
assert len(ledger["calls"]) == 3
print(json.dumps({"ledger": ledger, "build": call("/v1/build-info", "VERIFIER")}))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("evidence already exists")
    project = "p12-context-deploy-" + secrets.token_hex(5)
    service = deepcopy(yaml.safe_load(COMPOSE.read_text())["services"][SERVICE])
    service["container_name"] = project + "-context"
    service["image"] = "localhost/" + project + ":test"
    service["build"]["context"] = str(ROOT / "llm-security-control-plane")
    assert not service.get("ports") and not service.get("depends_on")
    document = {"name": project, "services": {SERVICE: service},
                "networks": {"guided": {"internal": True}}, "volumes": {"guided-p12-context-state": {}}}
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("GUIDED_", "COMPOSE_", "AWS_"))}
    environment.update({f"GUIDED_P12_CONTEXT_{role}_TOKEN": secrets.token_hex(32)
                        for role in ("CONTROL", "SERVICE", "VERIFIER")})

    def run(command, *, stdin=None, timeout=120):
        result = subprocess.run(command, input=stdin, env=environment, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stderr[-3000:] or "deployment check failed")
        return result.stdout

    with TemporaryDirectory(prefix=project) as temporary:
        path = Path(temporary) / "compose.yaml"
        path.write_text(yaml.safe_dump(document))
        base = ["docker", "compose", "--env-file", "/dev/null", "-f", str(path), "-p", project]
        try:
            run(base + ["up", "-d", "--build", "--wait", "--wait-timeout", "60"], timeout=240)
            def inspect():
                # Project labels bind cleanup ownership; only nonsecret identity fields are retained.
                raw = json.loads(run(["docker", "inspect", service["container_name"]]))[0]
                assert raw["Config"]["Labels"]["com.docker.compose.project"] == project
                assert raw["HostConfig"]["ReadonlyRootfs"] is True
                assert not raw["HostConfig"].get("PortBindings")
                assert raw["Config"]["User"] == "65532:65532"
                state = next(m for m in raw["Mounts"] if m["Destination"] == "/state")
                assert state["Type"] == "volume" and state["RW"] is True
                return {"container": raw["Id"], "image": raw["Image"], "volume": state["Name"]}
            before_id = inspect()
            before = json.loads(run(base + ["exec", "-T", SERVICE, "python", "-"], stdin=PROBE))
            run(base + ["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "60", SERVICE])
            after_id = inspect()
            after = json.loads(run(base + ["exec", "-T", SERVICE, "python", "-", before["ledger"]["suite_id"]], stdin=PROBE))
            assert before == after
            assert before_id["container"] != after_id["container"]
            assert before_id["volume"] == after_id["volume"] and before_id["image"] == after_id["image"]
            evidence = {"scope": "selected production Context Compose service; real TCP/SQLite and volume persistence; no whole P12/AWS/Browser",
                        "project": project, "compose_digest": hashlib.sha256(COMPOSE.read_bytes()).hexdigest(),
                        "before_identity": before_id, "after_identity": after_id, "result": after}
            serialized = json.dumps(evidence, ensure_ascii=False, indent=2)
            assert all(value not in serialized for key, value in environment.items() if key.startswith("GUIDED_"))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized + "\n")
            print(json.dumps({"project": project, "recreated": True, "preserved": True, "evidence": str(args.output)}))
        finally:
            # This generated project owns only its selected service, network and volume.
            run(base + ["down", "--volumes", "--timeout", "10"])


if __name__ == "__main__":
    main()
