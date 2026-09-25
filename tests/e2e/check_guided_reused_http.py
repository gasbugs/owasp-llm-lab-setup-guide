"""Reused learner boundaries on an isolated canonical Compose subset.

No host listener, AWS credentials, external model or external action is available.
Only this publisher's generated project and copied learner files are changed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from uuid import uuid4

from run_guided_h01_h04_h21_h22_learner_fixes import ACTIVITIES, assert_result
import run_guided_h05_learner_fix as h05
import run_guided_h06_learner_fix as h06
import run_guided_h07_learner_fix as h07
import run_guided_h08_learner_fix as h08

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
CANONICAL = ROOT / "examples/security-monitoring/compose.guided.yaml"
ACTIVITIES = {**ACTIVITIES,
    "H05": {"path": h05.FLOW_PATH, "services": ["guided-h05-nemo-dialog"],
            "replacements": [(h05.STARTER, h05.FIXED), (h05.STARTER_ROUTE, h05.FIXED_ROUTE)]},
    "H06": {"path": h06.ACTION_PATH,
            "services": ["guided-h06-action-provider", "guided-h06-nemo-action"],
            "replacements": [(h06.STARTER, h06.FIXED)]},
    "H07": {"path": h07.CONFIG_PATH, "services": ["guided-h07-content-safety"],
            "replacements": [(h07.STARTER_CONFIG, h07.FIXED_CONFIG)]},
    "H08": {"path": h08.PROMPTS_PATH, "services": ["guided-h08-self-check-input"],
            "replacements": [(h08.STARTER_PROMPTS, h08.FIXED_PROMPTS)]},
}
for activity, directory, artifact, services in (
    ("H09", "h09-presidio-redaction", "policy.py", ["guided-h09-presidio-redaction", "guided-h09-delivery-sink"]),
    ("H10", "h10-self-check-output", "config/prompts.yml", ["guided-h10-self-check-output"]),
    ("H11", "h11-rag-provenance", "policy.py", ["guided-h11-rag-provenance"]),
    ("H13", "h13-promptfoo", "promptfooconfig.yaml", ["guided-h13-promptfoo"]),
    ("H14", "h14-garak", "garak-config.yaml", ["guided-h14-garak"]),
    ("H15", "h15-pyrit", "attack.py", ["guided-h15-pyrit"]),
    ("H16", "h16-policy-promotion", "policy.py", ["guided-h16-policy-promotion"]),
):
    path = CONTROL / "guided-labs" / directory / artifact
    solution = CONTROL / "guided-solutions" / directory / Path(artifact).name
    ACTIVITIES[activity] = {"path": path, "services": services,
                            "replacements": [(path.read_text(), solution.read_text())]}
PUBLIC_CHECK = r'''
import http.cookiejar, json, sys, urllib.request
origin = 'http://127.0.0.1:8000'
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
opener.open(origin + '/').read()
bootstrap = json.load(opener.open(origin + '/api/bootstrap'))
request = urllib.request.Request(origin + '/api/practice/' + sys.argv[1] + '/verify',
    data=b'', headers={'Origin': origin, 'X-CSRF-Token': bootstrap['csrf_token']})
with opener.open(request, timeout=180) as response:
    print(json.dumps(json.load(response), ensure_ascii=False))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activities", nargs="+", choices=sorted(set(ACTIVITIES) - {"H01"}),
                        default=["H22", "H21"])
    parser.add_argument("--startup-only", action="store_true",
                        help="Start every canonical service without running a learner suite")
    parser.add_argument("--isolation-check", action="store_true",
                        help="Check a stopped learner, common restart and an isolated Tenant 02 Presidio")
    args = parser.parse_args()
    activities = args.activities
    if len(set(activities)) != len(activities):
        parser.error("activities must be distinct")
    project = "guided-reuse-check-" + uuid4().hex[:10]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GUIDED_", "AWS_", "COMPOSE_"))}
    env.update({key: secrets.token_hex(32)
                for key in re.findall(r"\$\{(\w+):\?", CANONICAL.read_text())})
    env.update(GUIDED_PROVIDER_MODE="contract", LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid()))
    model = json.loads(subprocess.check_output(["docker", "compose", "--env-file", "/dev/null",
        "-f", str(CANONICAL), "config", "--format", "json"], env=env, text=True))
    selected = {"guided-control-center", "guided-evidence-verifier"}
    for activity in activities:
        selected.update(ACTIVITIES[activity]["services"])
    pending = list(selected)
    while pending:
        for dependency in model["services"][pending.pop()].get("depends_on", {}):
            if dependency not in selected:
                selected.add(dependency)
                pending.append(dependency)
    if args.startup_only:
        selected = set(model["services"])
    records = []
    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        workspace = Path(directory)
        context = workspace / "control"
        shutil.copytree(CONTROL, context, ignore=shutil.ignore_patterns(".state", "__pycache__"))
        model["name"] = project
        model["services"] = {name: model["services"][name] for name in selected}
        model["networks"] = {"guided": {"name": project + "-network", "internal": True}}
        for name, service in model["services"].items():
            service["container_name"] = project + "-" + name
            if "build" in service:
                original_image = service["image"].split("/")[-1].split(":")[0]
                service["image"] = "localhost/" + project + "-" + original_image + ":test"
                service["build"]["context"] = str(context)
            service.pop("ports", None)
            service["restart"] = "no"
            for mount in service.get("volumes", []):
                if mount.get("type") == "bind":
                    source = Path(mount["source"])
                    if source.is_relative_to(CONTROL) and ".state" not in source.parts:
                        target = context / source.relative_to(CONTROL)
                    elif mount.get("read_only") and source.is_file() and source.is_relative_to(ROOT):
                        target = workspace / "readonly-config" / source.relative_to(ROOT)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, target)
                    elif mount["target"] in ("/tmp/.aws", "/state"):
                        target = workspace / ("empty-" + name + mount["target"].replace("/", "-"))
                        target.mkdir(exist_ok=True)
                    else:
                        raise RuntimeError("unreviewed bind mount in selected service: " + name)
                    mount["source"] = str(target)
        for volume in model.get("volumes", {}).values():
            volume.pop("name", None)
        model["services"]["guided-control-center"]["environment"].update(
            GUIDED_ALLOWED_HOSTS="127.0.0.1:8000,127.0.0.1:28097",
            GUIDED_ALLOWED_ORIGINS="http://127.0.0.1:8000")
        compose_path = workspace / "compose.json"
        compose_path.write_text(json.dumps(model))
        command = ["docker", "compose", "--env-file", "/dev/null", "-f", str(compose_path)]

        def compose(*arguments):
            subprocess.run(command + list(arguments), env=env, check=True)

        def verify(activity, variant):
            public = "P" + activity[1:]
            result = json.loads(subprocess.check_output(["docker", "exec",
                project + "-guided-control-center", "python", "-c", PUBLIC_CHECK, public], text=True))
            assert result["activity_id"] == public, result
            assert result["internal_activity_id"] == activity, result
            assert result["task_completed"] is (variant == "solution"), result
            if variant == "solution":
                assert result["security_verdict"] == "PASS", result
                if activity in ("H21", "H22"):
                    assert_result(activity, result)
            else:
                assert result["security_verdict"] == ("ERR" if activity in ("H13", "H14", "H15") else "HIT"), result
            records.append({"variant": variant, "result": result})

        tenant02_command = None
        if args.isolation_check:
            if len(activities) < 2:
                parser.error("isolation check requires two activities")
            tenant02_source = CONTROL / "compose.yaml"
            env.update({key: secrets.token_hex(32) for key in
                        re.findall(r"\$\{(\w+):\?", tenant02_source.read_text())})
            tenant02 = json.loads(subprocess.check_output([
                "docker", "compose", "--env-file", "/dev/null", "-f", str(tenant02_source),
                "config", "--format", "json"], env=env, text=True))
            service = tenant02["services"]["presidio"]
            service["container_name"] = project + "-tenant02-presidio"
            service["image"] = "localhost/" + project + "-tenant02-presidio:test"
            service["restart"] = "no"
            service["ports"] = [{"target": 8013, "published": "0", "host_ip": "127.0.0.1"}]
            tenant02_path = workspace / "tenant02.json"
            tenant02_path.write_text(json.dumps({"name": project + "-tenant02",
                "services": {"presidio": service},
                "networks": {"default": {"name": project + "-tenant02-network", "internal": True}}}))
            tenant02_command = ["docker", "compose", "--env-file", "/dev/null", "-f", str(tenant02_path)]

        def tenant02(*arguments):
            subprocess.run(tenant02_command + list(arguments), env=env, check=True)

        def verify_tenant02():
            code = '''import json, os, urllib.request
request = urllib.request.Request('http://127.0.0.1:8013/api/analyze',
    data=json.dumps({'stage': 'input', 'text': 'Hello world', 'request_id': 'coexist-normal'}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + os.environ['PRESIDIO_INTERNAL_TOKEN']})
result = json.load(urllib.request.urlopen(request, timeout=30))
assert result['valid'] is True and result['detections'] == [], result
print(json.dumps(result))'''
            result = json.loads(subprocess.check_output(["docker", "exec",
                project + "-tenant02-presidio", "python", "-c", code], text=True))
            records.append({"tenant02_normal": result})

        try:
            if tenant02_command:
                tenant02("up", "-d", "--build", "--wait", "--wait-timeout", "120")
                verify_tenant02()
            compose("build")
            if args.startup_only:
                compose("up", "-d")
                initializer = "guided-h20-grafana-reader"
                compose("up", "-d", "--no-deps", "--wait", "--wait-timeout", "240",
                        *sorted(selected - {initializer}))
                exit_code = subprocess.check_output(["docker", "wait", project + "-" + initializer],
                                                     text=True, timeout=60).strip()
                if exit_code != "0":
                    compose("logs", "--tail", "60", initializer, "guided-h20-grafana")
                assert exit_code == "0", "Grafana reader initialization failed"
                print(subprocess.check_output(command + ["ps", "--all", "--format", "json"],
                                              env=env, text=True))
                print("CANONICAL_STARTUP: all services started; no learner suite or AWS call")
                return
            # Later problems can run while earlier learners are still absent.
            for activity in activities:
                compose("up", "-d", "--wait", "--wait-timeout", "120",
                        "guided-evidence-verifier", "guided-control-center", *ACTIVITIES[activity]["services"])
                verify(activity, "starter")
            if tenant02_command:
                tenant02_id = subprocess.check_output(tenant02_command + ["ps", "-q", "presidio"], text=True).strip()
                compose("stop", *ACTIVITIES[activities[0]]["services"])
                compose("restart", "guided-control-center", "guided-evidence-verifier")
                compose("up", "-d", "--no-deps", "--wait", "--wait-timeout", "120",
                        "guided-control-center", "guided-evidence-verifier")
                verify(activities[1], "starter")
                assert subprocess.check_output(tenant02_command + ["ps", "-q", "presidio"], text=True).strip() == tenant02_id
                verify_tenant02()
                tenant02("down")
                tenant02("up", "-d", "--wait", "--wait-timeout", "120")
                verify_tenant02()
                verify(activities[1], "starter")
                compose("up", "-d", "--wait", "--wait-timeout", "120", *ACTIVITIES[activities[0]]["services"])
                records.append({"isolation": "Tenant 02 Presidio starts before/after Tenant 03; common restart with stopped learner; other learner remains usable"})
            for activity in activities:
                definition = ACTIVITIES[activity]
                path = context / definition["path"].relative_to(CONTROL)
                source = path.read_text()
                for before, after in definition["replacements"]:
                    assert source.count(before) == 1
                    source = source.replace(before, after)
                path.write_text(source)
                compose("build", *definition["services"])
                compose("up", "-d", "--no-deps", "--force-recreate", "--wait",
                        "--wait-timeout", "120", *definition["services"])
                verify(activity, "solution")
                if activity == activities[0] and len(activities) > 1:
                    verify(activities[1], "starter")
        finally:
            compose("down", "--volumes")
            if tenant02_command:
                tenant02("down", "--volumes")
    print(json.dumps({"scope": "isolated canonical HTTP services; no external provider or effects",
                      "records": records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
