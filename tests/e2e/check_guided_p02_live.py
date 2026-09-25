"""P02 packaged HTTP path; contract by default, AWS only with explicit options.

AWS refuses existing P02 resources, creates a test-owned set, and removes it after
successful verification. Failed/partial AWS work is preserved for diagnosis.
The source is built into a temporary context; the checkout Starter is unchanged.
This selected-service test does not certify the full operating Compose.
"""
import argparse
from contextlib import ExitStack
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler
from uuid import uuid4

from check_guided_p01_live import build, request
from guided_live_stack import LiveStack
from p02_markdown import extract_solution

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
LAB = CONTROL / "guided-labs/h02-document-ingestion"
RPC = '''
import json, sys, urllib.request, urllib.error
url, token, body = json.loads(sys.argv[1])
headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
req = urllib.request.Request(url, headers=headers, data=None if body is None else json.dumps(body).encode())
try:
    response = urllib.request.urlopen(req, timeout=200)
except urllib.error.HTTPError as error:
    response = error
with response:
    print(json.dumps([response.status, json.load(response)]))
'''


def rpc(project, origin, path, token="", body=None):
    return json.loads(subprocess.check_output(["docker", "exec", project + "-verifier", "python", "-c", RPC,
        json.dumps([origin + path, token, body])], text=True, timeout=210))


def aws_scope(project, action, payload):
    code = (ROOT / "tests/e2e/p02_aws_scope.py").read_text()
    return json.loads(subprocess.check_output(["docker", "exec", project + "-gateway", "python", "-c", code,
        action, json.dumps(payload)], text=True, timeout=180))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--starter", action="store_true")
    choice.add_argument("--source", type=Path)
    choice.add_argument("--markdown", type=Path)
    parser.add_argument("--expect-incomplete", action="store_true")
    parser.add_argument("--browser-python", type=Path)
    parser.add_argument("--aws-config-dir", type=Path)
    parser.add_argument("--aws-profile", default="default")
    parser.add_argument("--aws-account")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve previous evidence")
    if args.aws_config_dir and (not args.aws_config_dir.is_dir() or not re.fullmatch(r"\d{12}", args.aws_account or "")):
        parser.error("AWS requires an existing credential directory and exact account ID")
    if args.aws_account and not args.aws_config_dir:
        parser.error("AWS account requires the explicit credential directory")
    mode = "aws" if args.aws_config_dir else "contract"
    source = (extract_solution(args.markdown.read_text()).encode("utf-8") if args.markdown
              else (LAB / "learner.py" if args.starter else args.source).read_bytes())
    if len(source) > 65536:
        parser.error("source exceeds runner limit")
    incomplete = args.starter or args.expect_incomplete
    project = "guided-p02-check-" + uuid4().hex[:10]
    proof = {"scope": "selected packaged HTTP services; not full Compose",
             "project": project, "provider_mode": mode, "starter": args.starter,
             "source_digest": hashlib.sha256(source).hexdigest()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with ExitStack() as cleanup:
            temporary = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="p02-build-")))
            target = temporary / "guided-labs/h02-document-ingestion"
            target.mkdir(parents=True)
            for name in ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py",
                         "Containerfile", "requirements.txt"):
                shutil.copyfile(LAB / name, target / name)
            (target / "learner.py").write_bytes(source)
            learner_image = build("learner", target / "Containerfile", temporary, project)
            gateway_image = build("gateway", CONTROL / "guided-bedrock-gateway/Containerfile", CONTROL, project)
            verifier_image = build("verifier", CONTROL / "guided-evidence-verifier/Containerfile", CONTROL, project)
            network = project + "_default"
            subprocess.run(["docker", "network", "create", "--internal", network], check=True)
            cleanup.callback(subprocess.run, ["docker", "network", "rm", network], check=True)
            if mode == "aws":
                egress = project + "-aws"
                subprocess.run(["docker", "network", "create", egress], check=True)
                cleanup.callback(subprocess.run, ["docker", "network", "rm", egress], check=True)
            live = LiveStack(ROOT, project, "H02", "http://learner:8000")
            cleanup.callback(live.close)
            gateway_env = {name: "publisher-test-" + name.lower()
                for path in (CONTROL / "guided-bedrock-gateway").glob("*.py")
                for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', path.read_text())}
            gateway_env.update(GUIDED_PROVIDER_MODE=mode, AWS_REGION="us-east-1",
                GUIDED_H02_GATEWAY_TOKEN="publisher-p02-runtime",
                GUIDED_LAB02_PROVISION_TOKEN="publisher-p02-provision",
                GUIDED_VERIFIER_GATEWAY_TOKEN="publisher-p02-read")
            extra = ["--network-alias", "gateway", "--tmpfs", "/state:uid=65532,gid=65532"]
            if mode == "aws":
                gateway_env.update(AWS_PROFILE=args.aws_profile, AWS_DEFAULT_REGION="us-east-1",
                    AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE="/aws/config",
                    AWS_SHARED_CREDENTIALS_FILE="/aws/credentials", AWS_MAX_ATTEMPTS="1")
                extra = ["--network-alias", "gateway", "--network", egress,
                         "--tmpfs", f"/state:uid={os.getuid()},gid={os.getgid()}",
                         "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{args.aws_config_dir.resolve()}:/aws:ro"]
            live.launch("gateway", gateway_image, gateway_env, extra)
            live.launch("learner", learner_image, {
                "GUIDED_GATEWAY_URL": "http://gateway:8080", "GUIDED_H02_GATEWAY_TOKEN": "publisher-p02-runtime",
                "GUIDED_CONTROL_LAB02_TOKEN": "publisher-test-control",
                "GUIDED_VERIFIER_LAB02_TOKEN": "publisher-test-verifier"}, ["--network-alias", "learner"])
            live.start_verifier(verifier_image, {"GUIDED_LAB02_URL": "http://learner:8000",
                "GUIDED_VERIFIER_LAB02_TOKEN": "publisher-test-verifier",
                "GUIDED_BEDROCK_GATEWAY_URL": "http://gateway:8080",
                "GUIDED_VERIFIER_GATEWAY_TOKEN": "publisher-p02-read"})
            origin = live.start_browser({"GUIDED_LAB02_URL": "http://learner:8000",
                "GUIDED_CONTROL_LAB02_TOKEN": "publisher-test-control"})
            opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()))
            deadline = time.monotonic() + 60
            while True:
                try:
                    if request(opener, origin + "/readyz")[0] == 200:
                        break
                except (URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("common UI startup")
                time.sleep(.5)
            for service in ("http://gateway:8080", "http://learner:8000", "http://verifier:8000"):
                assert rpc(project, service, "/readyz")[0] == 200
            if mode == "aws":
                proof["aws_preflight"] = aws_scope(project, "preflight", {"account_id": args.aws_account})
            status, prepared = rpc(project, "http://gateway:8080", "/v1/h02/provision",
                                   "publisher-p02-provision", {"execution_id": str(uuid4())})
            proof["provision"] = prepared
            assert status == 200
            with opener.open(origin + "/", timeout=5) as index:
                assert index.status == 200
            status, bootstrap = request(opener, origin + "/api/bootstrap")
            assert status == 200
            headers = {"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]}
            if args.browser_python:
                browser_output = args.output.with_suffix(".browser.json")
                command = [str(args.browser_python.absolute()), str(ROOT / "tests/browser/check_guided_p02_live.py"),
                           origin, str(browser_output), "--source-digest", proof["source_digest"]]
                if incomplete:
                    command.append("--incomplete")
                subprocess.run(command, check=True, timeout=300)
                browser_proof = json.loads(browser_output.read_text())
                status, response = browser_proof["http_status"], browser_proof["response"]
                proof["browser"] = str(browser_output)
            else:
                status, response = request(opener, origin + "/api/practice/P02/verify", headers=headers, body=b"")
            proof.update(http_status=status, response=response, images=live.images)
            assert status == 200
            suite = response["execution_id"]
            assert response["activity_id"] == "P02" and response["task_completed"] is (not incomplete)
            assert response["security_verdict"] == ("ERR" if incomplete else "PASS")
            status, root = rpc(project, "http://learner:8000", "/v1/receipts/" + suite, "publisher-test-verifier")
            proof["root"] = root
            assert status == 200 and len(root["cases"]) == 22 and root["run_state"] == "finished"
            assert root["build"] == root["final_build"]
            assert root["build"]["source_digest"] == proof["source_digest"]
            ledgers = []
            for row in root["cases"]:
                status, ledger = rpc(project, "http://gateway:8080", "/v1/p02/executions/" + row["execution_id"], "publisher-p02-read")
                assert status == 200 and ledger["closed"] is True and ledger["suite_id"] == suite
                ledgers.append(ledger)
            proof["ledgers"] = ledgers
            if args.starter:
                assert all(not row["calls"] for row in ledgers)
            elif not incomplete:
                assert sum(len(row["calls"]) for row in ledgers) == 8
                assert len(response["result"]["cases"]) == 22
                assert response["result"]["provider_mode"] == mode
            status, again = rpc(project, "http://verifier:8000", "/v1/verify/p02",
                                "publisher-test-control", {"suite_id": suite})
            assert status == 200 and again["task_completed"] is (not incomplete)
            assert rpc(project, "http://learner:8000", "/v1/receipts/" + suite, "publisher-test-verifier")[1] == root
            assert rpc(project, "http://verifier:8000", "/v1/verify/p02", body={"suite_id": suite})[0] == 401
            assert rpc(project, "http://verifier:8000", "/v1/verify/p02", "publisher-test-control",
                       {"suite_id": suite, "task_completed": True})[0] == 422
            rejected, _ = request(opener, origin + "/api/practice/P02/verify",
                headers={**headers, "Content-Type": "application/json"}, body=b'{"task_completed":true}')
            assert rejected == 422
            if mode == "aws":
                try:
                    proof["aws_reuse"] = aws_scope(project, "reuse", {"account_id": args.aws_account,
                        "preflight": proof["aws_preflight"], "state": prepared})
                    status, reused = rpc(project, "http://gateway:8080", "/v1/h02/provision",
                        "publisher-p02-provision", {"execution_id": str(uuid4())})
                    proof["reused_provision"] = reused
                    assert status == 200 and reused["knowledge_base_id"] == prepared["knowledge_base_id"]
                    assert reused["data_source_id"] == prepared["data_source_id"]
                    status, after_reuse = rpc(project, "http://verifier:8000", "/v1/verify/p02",
                        "publisher-test-control", {"suite_id": suite})
                    assert status == 200 and after_reuse["task_completed"] is (not incomplete)
                    proof["reverified_after_reuse"] = after_reuse
                finally:
                    state_status, latest_state = rpc(project, "http://gateway:8080", "/v1/h02/resources", "publisher-p02-read")
                    assert state_status == 200
                    proof["aws_cleanup"] = aws_scope(project, "cleanup", {"account_id": args.aws_account,
                        "preflight": proof["aws_preflight"], "state": latest_state,
                        "execution_ids": [row["execution_id"] for row in root["cases"]]})
            proof.update(verified=True, submitted_verdict_status=rejected, reverified=again)
    finally:
        remaining = subprocess.check_output(["docker", "ps", "-a", "--format", "{{.Names}}"], text=True).splitlines()
        networks = subprocess.check_output(["docker", "network", "ls", "--format", "{{.Name}}"], text=True).splitlines()
        proof["owned_containers_removed"] = not any(name.startswith(project + "-") for name in remaining)
        proof["owned_networks_removed"] = not any(name.startswith(project) for name in networks)
        args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
    assert proof["owned_containers_removed"] and proof["owned_networks_removed"]
    print(json.dumps({"verified": True, "starter": args.starter, "project": project}), flush=True)


if __name__ == "__main__":
    main()
