"""Default-CMD P03 learner/Gateway/common verifier over isolated Docker TCP.

Contract by default; explicit AWS options require the Browser preparation path.
AWS refuses existing resources and cleans only a proven, complete test creation.
Partial AWS preparation is preserved for inspection. No full Compose proof.
The selected source is built into a temporary context; checkout stays unchanged.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen
from uuid import uuid4

from check_guided_p01_live import build
from guided_live_stack import LiveStack
from p03_markdown import extract_solution

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
LAB = CONTROL / "guided-labs/h03-ingestion-search"
RPC = '''
import json, sys, urllib.request, urllib.error
url, token, body = json.loads(sys.argv[1])
request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
    "Content-Type": "application/json"}, data=None if body is None else json.dumps(body).encode())
try:
    response = urllib.request.urlopen(request, timeout=200)
except urllib.error.HTTPError as error:
    response = error
with response:
    print(json.dumps([response.status, json.load(response)]))
'''


def rpc(project, service, path, token="", body=None):
    return json.loads(subprocess.check_output(["docker", "exec", project + "-verifier", "python", "-c", RPC,
        json.dumps(["http://" + service + path, token, body])], text=True, timeout=210))


def aws_call(project, action, payload):
    code = '''
import json, sys
from p03_aws_scope import preflight
from p03_aws_cleanup import cleanup_created
action, payload = sys.argv[1], json.loads(sys.argv[2])
if action == "preflight":
    result = preflight(payload["account_id"])
elif action == "cleanup":
    result = cleanup_created(payload["account_id"], payload["before"], payload["prepared"], "/state/evidence.sqlite3")
else:
    raise ValueError("unknown publisher operation")
print(json.dumps(result))
'''
    return json.loads(subprocess.check_output(["docker", "exec", project + "-gateway", "python", "-c", code,
        action, json.dumps(payload)], text=True, timeout=200))


def cleanup_aws(project, account_id, proof, preparation_path):
    logs = subprocess.check_output(
        ["docker", "logs", "--tail", "50", project + "-gateway"], text=True, stderr=subprocess.STDOUT)
    proof["gateway_preparation_diagnostics"] = [line for line in logs.splitlines() if re.fullmatch(
        r"P03 source preparation failed: operation=[A-Za-z_][A-Za-z0-9_]* type=[A-Za-z_][A-Za-z0-9_]*", line)]
    if preparation_path.exists():
        proof["aws_preparation"] = json.loads(preparation_path.read_text())
    prepared = proof.get("aws_preparation", {}).get("preparation")
    if not isinstance(prepared, dict) or prepared.get("state") != "ready":
        operation_id = proof.get("aws_preparation", {}).get("detail", {}).get("operation_id")
        if operation_id:
            status, journal = rpc(project, "gateway:8080", "/v1/p03/preparations/" + operation_id,
                                  "publisher-p03-read")
            proof["aws_preparation_journal"] = {"http_status": status, "journal": journal}
        proof["aws_cleanup"] = {"performed": False, "reason": "no complete preparation; inspect partial AWS resources"}
        return
    proof["aws_cleanup"] = aws_call(project, "cleanup", {
        "account_id": account_id, "before": proof["aws_preflight"], "prepared": prepared})


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
    parser.add_argument("--recreate-learner", action="store_true",
                        help="replace the learner container, preserving only its named receipt volume")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("preserve existing evidence; choose a new output")
    if args.aws_config_dir and (not args.aws_config_dir.is_dir()
            or not re.fullmatch(r"\d{12}", args.aws_account or "") or not args.browser_python):
        parser.error("AWS requires a credential directory, exact account ID and Browser Python")
    if args.aws_account and not args.aws_config_dir:
        parser.error("AWS account requires an explicit credential directory")
    mode = "aws" if args.aws_config_dir else "contract"
    source = (extract_solution(args.markdown.read_bytes().decode("utf-8")).encode("utf-8")
              if args.markdown else (LAB / "learner.py" if args.starter else args.source).read_bytes())
    if len(source) > 65536:
        parser.error("source exceeds runner limit")
    project = "guided-p03-check-" + uuid4().hex[:10]
    proof = {"scope": "selected default-CMD services; requested provider=" + mode + "; not full Compose",
             "project": project, "provider_mode": mode, "starter": args.starter,
             "source_digest": hashlib.sha256(source).hexdigest()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with ExitStack() as cleanup:
            temporary = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="p03-build-")))
            target = temporary / "guided-labs/h03-ingestion-search"
            target.mkdir(parents=True)
            for name in ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py",
                         "Containerfile", "requirements.txt"):
                shutil.copyfile(LAB / name, target / name)
            (target / "learner.py").write_bytes(source)
            learner = build("learner", target / "Containerfile", temporary, project)
            gateway = build("gateway", CONTROL / "guided-bedrock-gateway/Containerfile", CONTROL, project)
            verifier = build("verifier", CONTROL / "guided-evidence-verifier/Containerfile", CONTROL, project)
            network = project + "_default"
            subprocess.run(["docker", "network", "create", "--internal", network], check=True)
            cleanup.callback(subprocess.run, ["docker", "network", "rm", network], check=True)
            if mode == "aws":
                egress = project + "-aws"
                subprocess.run(["docker", "network", "create", egress], check=True)
                cleanup.callback(subprocess.run, ["docker", "network", "rm", egress], check=True)
            volume = project + "-receipts"
            subprocess.run(["docker", "volume", "create", volume], check=True)
            cleanup.callback(subprocess.run, ["docker", "volume", "rm", volume], check=True)
            live = LiveStack(ROOT, project, "H03", "http://learner:8000")
            cleanup.callback(live.close)
            env = {name: "publisher-test-" + name.lower()
                   for path in (CONTROL / "guided-bedrock-gateway").glob("*.py")
                   for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', path.read_text())}
            env.update(GUIDED_PROVIDER_MODE=mode, AWS_REGION="us-east-1",
                       GUIDED_LAB03_PROVISION_TOKEN="publisher-p03-provision",
                       GUIDED_H03_GATEWAY_TOKEN="publisher-p03-runtime", GUIDED_VERIFIER_GATEWAY_TOKEN="publisher-p03-read")
            gateway_extra = ["--network-alias", "gateway", "--tmpfs", "/state:uid=65532,gid=65532"]
            if mode == "aws":
                env.update(AWS_PROFILE=args.aws_profile, AWS_EC2_METADATA_DISABLED="true",
                    AWS_CONFIG_FILE="/aws/config", AWS_SHARED_CREDENTIALS_FILE="/aws/credentials",
                    PYTHONPATH="/app:/publisher")
                gateway_extra = ["--network-alias", "gateway", "--network", egress,
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--tmpfs", f"/state:uid={os.getuid()},gid={os.getgid()}",
                    "--mount", f"type=bind,source={args.aws_config_dir.resolve()},target=/aws,readonly",
                    "--mount", f"type=bind,source={ROOT / 'tests/e2e'},target=/publisher,readonly"]
            live.launch("gateway", gateway, env, gateway_extra)
            learner_env = {"GUIDED_BEDROCK_GATEWAY_URL": "http://gateway:8080",
                "GUIDED_H03_GATEWAY_TOKEN": "publisher-p03-runtime", "GUIDED_CONTROL_LAB03_TOKEN": "publisher-test-control",
                "GUIDED_VERIFIER_LAB03_TOKEN": "publisher-test-verifier",
                "GUIDED_H03_DATABASE": "/state/p03-receipts.sqlite3"}
            learner_extra = ["--network-alias", "learner", "--mount", "type=volume,source=" + volume + ",target=/state"]
            live.launch("learner", learner, learner_env, learner_extra)
            live.start_verifier(verifier, {"GUIDED_LAB03_URL": "http://learner:8000",
                "GUIDED_VERIFIER_LAB03_TOKEN": "publisher-test-verifier", "GUIDED_BEDROCK_GATEWAY_URL": "http://gateway:8080",
                "GUIDED_VERIFIER_GATEWAY_TOKEN": "publisher-p03-read"})
            for service in ("gateway:8080", "learner:8000", "verifier:8000"):
                deadline = time.monotonic() + 30
                while True:
                    try:
                        if rpc(project, service, "/readyz")[0] == 200:
                            break
                    except subprocess.CalledProcessError:
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("service startup: " + service)
                    time.sleep(.25)
            if args.browser_python:
                origin = live.start_browser({"GUIDED_LAB03_URL": "http://learner:8000",
                    "GUIDED_CONTROL_LAB03_TOKEN": "publisher-test-control",
                    "GUIDED_BEDROCK_GATEWAY_URL": "http://gateway:8080",
                    "GUIDED_LAB03_PROVISION_TOKEN": "publisher-p03-provision"})
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with urlopen(origin + "/readyz", timeout=2) as response:
                            if response.status == 200:
                                break
                    except (URLError, TimeoutError):
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("UI startup")
                    time.sleep(.25)
                browser_output = args.output.with_suffix(".browser.json")
                command = [str(args.browser_python.absolute()), str(ROOT / "tests/browser/check_guided_p03_live.py"),
                           origin, str(browser_output), "--source-digest", proof["source_digest"]]
                if mode == "aws":
                    proof["aws_preflight"] = aws_call(project, "preflight", {"account_id": args.aws_account})
                    preparation_path = browser_output.with_suffix(".preparation.json")
                    cleanup.callback(cleanup_aws, project, args.aws_account, proof, preparation_path)
                    command += ["--prepare-aws"]
                if args.starter or args.expect_incomplete:
                    command.append("--incomplete")
                subprocess.run(command, check=True, timeout=850 if mode == "aws" else 300)
                proof["browser"] = json.loads(browser_output.read_text())
                suite = proof["browser"]["response"]["execution_id"]
                status, root = rpc(project, "learner:8000", "/v1/receipts/" + suite, "publisher-test-verifier")
                proof["scope"] = "selected default-CMD Browser and TCP services; " + mode + "; not full Compose"
            else:
                suite = str(uuid4())
                status, root = rpc(project, "learner:8000", "/v1/run", "publisher-test-control", {"suite_id": suite})
            proof["root"] = root
            assert status == 200 and root["run_state"] == "finished" and len(root["cases"]) == 19
            assert root["build"]["source_digest"] == proof["source_digest"]
            status, result = rpc(project, "verifier:8000", "/v1/verify/p03", "publisher-test-control", {"suite_id": suite})
            proof["verification"] = result
            expected = not (args.starter or args.expect_incomplete)
            assert status == 200 and result["task_completed"] is expected
            assert result["security_verdict"] == ("PASS" if expected else "ERR")
            if expected:
                assert result["result"]["provider_mode"] == mode and len(result["result"]["cases"]) == 19
                assert result["result"]["source_digest"] == proof["source_digest"]
            assert rpc(project, "verifier:8000", "/v1/verify/p03", "wrong", {"suite_id": suite})[0] == 401
            assert rpc(project, "verifier:8000", "/v1/verify/p03", "publisher-test-control",
                       {"suite_id": suite, "task_completed": True})[0] == 422
            assert rpc(project, "learner:8000", "/v1/run", "publisher-test-control", {"suite_id": suite})[0] == 409
            status, repeated = rpc(project, "verifier:8000", "/v1/verify/p03", "publisher-test-control", {"suite_id": suite})
            assert status == 200 and repeated["task_completed"] is expected
            assert rpc(project, "learner:8000", "/v1/receipts/" + suite, "publisher-test-verifier")[1] == root
            if args.recreate_learner:
                def inspect(role):
                    return json.loads(subprocess.check_output(
                        ["docker", "inspect", project + "-" + role], text=True))[0]
                before = inspect("learner")
                gateway_before = inspect("gateway")["Id"]
                subprocess.run(["docker", "stop", project + "-learner"], check=True)
                subprocess.run(["docker", "network", "disconnect", network, project + "-learner"], check=True)
                live.launch("learner-recreated", learner, learner_env, learner_extra)
                deadline = time.monotonic() + 30
                while True:
                    try:
                        if rpc(project, "learner:8000", "/readyz")[0] == 200:
                            break
                    except subprocess.CalledProcessError:
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("recreated learner startup")
                    time.sleep(.25)
                after = inspect("learner-recreated")
                assert before["Id"] != after["Id"] and before["Image"] == after["Image"]
                assert inspect("gateway")["Id"] == gateway_before
                for container in (before, after):
                    mounts = [item for item in container["Mounts"] if item["Destination"] == "/state"]
                    assert len(mounts) == 1 and mounts[0]["Type"] == "volume" and mounts[0]["Name"] == volume
                assert rpc(project, "learner:8000", "/v1/receipts/" + suite, "publisher-test-verifier")[1] == root
                assert rpc(project, "learner:8000", "/v1/run", "publisher-test-control", {"suite_id": suite})[0] == 409
                status, preserved = rpc(project, "verifier:8000", "/v1/verify/p03", "publisher-test-control", {"suite_id": suite})
                assert status == 200 and preserved["task_completed"] is expected
                assert preserved["security_verdict"] == ("PASS" if expected else "ERR")
                proof["recreation"] = {"before_container": before["Id"], "after_container": after["Id"],
                    "volume": volume, "receipt_unchanged": True, "replay_status": 409,
                    "gateway_unchanged": True, "verification": preserved}
            proof.update(images=live.images, checked=True, recheck_completed=repeated["task_completed"])
    finally:
        proof["remaining_containers"] = subprocess.check_output(["docker", "ps", "-aq", "--filter", "name=" + project], text=True).split()
        proof["remaining_networks"] = subprocess.check_output(["docker", "network", "ls", "-q", "--filter", "name=" + project], text=True).split()
        proof["remaining_volumes"] = subprocess.check_output(["docker", "volume", "ls", "-q", "--filter", "name=" + project], text=True).split()
        args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
    assert not proof["remaining_containers"] and not proof["remaining_networks"] and not proof["remaining_volumes"]
    print(json.dumps({"checked": proof["checked"], "starter": args.starter, "output": str(args.output)}))


if __name__ == "__main__":
    main()
