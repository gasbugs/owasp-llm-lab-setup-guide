#!/usr/bin/env python3
"""Legacy H10-H16 checks excluding P12; P12 and P17-P20 use isolated checkers."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
COMPOSE_ENV_FILE: Path | None = None

ACTIVITIES = {
    "H10": (
        CONTROL / "guided-labs/h10-self-check-output/config/prompts.yml",
        CONTROL / "guided-solutions/h10-self-check-output/prompts.yml",
        "guided-h10-self-check-output",
        "llm-security-guided-h10-self-check-output",
    ),
    "H11": (
        CONTROL / "guided-labs/h11-rag-provenance/policy.py",
        CONTROL / "guided-solutions/h11-rag-provenance/policy.py",
        "guided-h11-rag-provenance",
        "llm-security-guided-h11-rag-provenance",
    ),
    "H13": (
        CONTROL / "guided-labs/h13-promptfoo/promptfooconfig.yaml",
        CONTROL / "guided-solutions/h13-promptfoo/promptfooconfig.yaml",
        "guided-h13-promptfoo",
        "llm-security-guided-h13-promptfoo",
    ),
    "H14": (
        CONTROL / "guided-labs/h14-garak/garak-config.yaml",
        CONTROL / "guided-solutions/h14-garak/garak-config.yaml",
        "guided-h14-garak",
        "llm-security-guided-h14-garak",
    ),
    "H15": (
        CONTROL / "guided-labs/h15-pyrit/attack.py",
        CONTROL / "guided-solutions/h15-pyrit/attack.py",
        "guided-h15-pyrit",
        "llm-security-guided-h15-pyrit",
    ),
    "H16": (
        CONTROL / "guided-labs/h16-policy-promotion/policy.py",
        CONTROL / "guided-solutions/h16-policy-promotion/policy.py",
        "guided-h16-policy-promotion",
        "llm-security-guided-h16-policy-promotion",
    ),
}

def compose(*arguments: str) -> None:
    command = ["docker", "compose"]
    if COMPOSE_ENV_FILE is not None:
        command.extend(("--env-file", str(COMPOSE_ENV_FILE)))
    command.extend(("--file", str(COMPOSE), *arguments))
    subprocess.run(command, cwd=ROOT, check=True)


def wait_healthy(container: str, seconds: int = 180) -> None:
    for _ in range(seconds):
        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
            text=True,
            capture_output=True,
        )
        if state.returncode == 0 and state.stdout.strip() == "healthy":
            return
        time.sleep(1)
    raise RuntimeError(f"{container} did not become healthy")


def rebuild(service: str, container: str) -> None:
    compose("build", service)
    compose("up", "-d", "--no-deps", "--force-recreate", service)
    wait_healthy(container)


def new_session(origin: str) -> tuple[urllib.request.OpenerDirector, str]:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    return opener, bootstrap["csrf_token"]


def verify(origin: str, activity: str) -> dict:
    opener, csrf = new_session(origin)
    request = urllib.request.Request(
        f"{origin}/api/hands-on/{activity}/verify",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": csrf},
    )
    with opener.open(request, timeout=360) as response:
        result = json.load(response)
    assert result["course_verdict"] == "PASS", result
    assert result["verified_by"] == "guided-evidence-verifier", result
    Path(f"/tmp/guided-{activity.lower()}-pass.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result


def restore(originals: dict[Path, bytes]) -> None:
    for path, content in originals.items():
        path.write_bytes(content)


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    parser.add_argument("--start-at", choices=list(ACTIVITIES), default="H10")
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()
    origin = args.url.rstrip("/")

    originals: dict[Path, bytes] = {}
    try:
        start_number = int(args.start_at[1:])
        for activity, (learner, solution, service, container) in ACTIVITIES.items():
            if int(activity[1:]) < start_number:
                continue
            originals[learner] = learner.read_bytes()
            learner.write_bytes(solution.read_bytes())
            rebuild(service, container)
            result = verify(origin, activity)
            print(f"{activity.lower()}_learner_edit_rebuild=PASS evidence={len(result.get('evidence', []))}")

    finally:
        restore(originals)
        services = [
            item[2]
            for activity, item in ACTIVITIES.items()
            if int(activity[1:]) >= start_number
        ]
        if services:
            compose("build", *services)
            compose("up", "-d", "--no-deps", "--force-recreate", *services)
        for activity, item in ACTIVITIES.items():
            if int(activity[1:]) >= start_number:
                wait_healthy(item[3])

    print("h10_h16_starter_restore=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
