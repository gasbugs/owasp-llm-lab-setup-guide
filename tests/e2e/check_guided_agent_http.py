"""P21/P22 synthetic approval boundaries on an isolated canonical Compose subset.

No host listener, AWS credentials, external model or external action is available.
Only this publisher's generated project and copied learner files are changed.
"""
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

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
CANONICAL = ROOT / "examples/security-monitoring/compose.guided.yaml"
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
    project = "guided-agent-check-" + uuid4().hex[:10]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GUIDED_", "AWS_", "COMPOSE_"))}
    env.update({key: secrets.token_hex(32)
                for key in re.findall(r"\$\{(\w+):\?", CANONICAL.read_text())})
    env.update(GUIDED_PROVIDER_MODE="contract", LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid()))
    model = json.loads(subprocess.check_output(["docker", "compose", "--env-file", "/dev/null",
        "-f", str(CANONICAL), "config", "--format", "json"], env=env, text=True))
    selected = {"guided-control-center", "guided-evidence-verifier"}
    for activity in ("H21", "H22"):
        selected.update(ACTIVITIES[activity]["services"])
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
            service["image"] = "localhost/" + project + "-" + name + ":test"
            service["build"]["context"] = str(context)
            service.pop("ports", None)
            service["restart"] = "no"
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
                assert_result(activity, result)
            else:
                assert result["security_verdict"] == "HIT", result
            records.append({"variant": variant, "result": result})

        try:
            compose("build")
            # P22 first: P21's containers are not even started yet.
            compose("up", "-d", "--wait", "--wait-timeout", "120",
                    "guided-evidence-verifier", "guided-control-center", *ACTIVITIES["H22"]["services"])
            verify("H22", "starter")
            compose("up", "-d", "--wait", "--wait-timeout", "120", *ACTIVITIES["H21"]["services"])
            verify("H21", "starter")
            for activity in ("H22", "H21"):
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
                if activity == "H22":
                    verify("H21", "starter")
        finally:
            compose("down", "--volumes")
    print(json.dumps({"scope": "P21/P22 real HTTP and MCP; synthetic provider and effects",
                      "records": records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
