#!/usr/bin/env python3
"""Prove the H09 Presidio policy edit, then restore the Starter image."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "llm-security-control-plane/guided-labs/h09-presidio-redaction/policy.py"
SOLUTION_PATH = ROOT / "llm-security-control-plane/guided-solutions/h09-presidio-redaction/policy.py"
COMPOSE_PATH = ROOT / "examples/security-monitoring/compose.guided.yaml"
COMPOSE_ENV_FILE: Path | None = None


def compose(*arguments: str) -> None:
    command = ["docker", "compose"]
    if COMPOSE_ENV_FILE is not None:
        command.extend(("--env-file", str(COMPOSE_ENV_FILE)))
    command.extend(("--file", str(COMPOSE_PATH), *arguments))
    subprocess.run(command, cwd=ROOT, check=True)


def wait_healthy(container: str) -> None:
    for _ in range(180):
        completed = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
            text=True,
            capture_output=True,
            check=True,
        )
        if completed.stdout.strip() == "healthy":
            return
        time.sleep(1)
    raise RuntimeError(f"{container} did not become healthy")


def rebuild_h09() -> None:
    compose("build", "guided-h09-presidio-redaction")
    compose(
        "up",
        "-d",
        "--no-deps",
        "--force-recreate",
        "guided-h09-presidio-redaction",
    )
    wait_healthy("llm-security-guided-h09-presidio-redaction")


def verify(origin: str) -> dict:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    request = urllib.request.Request(
        f"{origin}/api/hands-on/H09/verify",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]},
    )
    with opener.open(request, timeout=180) as response:
        return json.load(response)


def assert_starter_hit(payload: dict) -> None:
    assert payload["course_verdict"] == "HIT", payload
    result = payload["result"]
    assert result["framework"] == "microsoft-presidio"
    assert result["framework_version"] == "2.2.362"
    assert result["entities"] == ["EMAIL_ADDRESS"]
    assert result["official_kr_rrn"] is False
    assert result["delivery_count"] == 4
    assert result["raw_risk_cases"] == [
        "input-email",
        "input-kr-rrn",
        "output-email",
    ]
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "learner@example.com" not in serialized
    assert "900101-1234568" not in serialized
    assert "security-team@example.com" not in serialized
    assert '"capability"' not in serialized


def assert_fixed_pass(payload: dict) -> None:
    assert payload["course_verdict"] == "PASS", payload
    result = payload["result"]
    assert result["framework"] == "microsoft-presidio"
    assert result["framework_version"] == "2.2.362"
    assert result["entities"] == ["EMAIL_ADDRESS", "KR_RRN"]
    assert result["official_kr_rrn"] is True
    assert result["delivery_count"] == 4
    assert result["raw_risk_cases"] == []
    assert all(not item["raw_marker_observed"] for item in result["deliveries"])


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()
    origin = args.url.rstrip("/")

    original = POLICY_PATH.read_bytes()
    fixed = SOLUTION_PATH.read_bytes()
    if original == fixed:
        raise RuntimeError("H09 Starter policy already matches the completed policy")

    starter = verify(origin)
    assert_starter_hit(starter)
    print("h09_starter=HIT deliveries=4 raw_risk_cases=3")

    try:
        shutil.copyfile(SOLUTION_PATH, POLICY_PATH)
        rebuild_h09()
        completed = verify(origin)
        assert_fixed_pass(completed)
        print("h09_learner_edit_rebuild=PASS deliveries=4 raw_risk_cases=0 official_kr_rrn=true")
    finally:
        POLICY_PATH.write_bytes(original)
        rebuild_h09()

    restored = verify(origin)
    assert_starter_hit(restored)
    print("h09_starter_restore=HIT deliveries=4 raw_risk_cases=3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
