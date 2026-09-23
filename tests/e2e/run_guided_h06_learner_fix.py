#!/usr/bin/env python3
"""Prove the H06 allowlist edit with a real rebuild, then restore Starter."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTION_PATH = ROOT / "llm-security-control-plane/guided-labs/h06-nemo-action/actions.py"
COMPOSE_PATH = ROOT / "examples/security-monitoring/compose.guided.yaml"
COMPOSE_ENV_FILE: Path | None = None
STARTER = '''ALLOWED_ACTIONS = frozenset(
    {
        "get_account_balance",
        "transfer_training_funds",
        "get_account_balance_and_transfer",
    }
)'''
FIXED = 'ALLOWED_ACTIONS = frozenset({"get_account_balance"})'


def compose(*arguments: str) -> None:
    command = ["docker", "compose"]
    if COMPOSE_ENV_FILE is not None:
        command.extend(("--env-file", str(COMPOSE_ENV_FILE)))
    command.extend(("--file", str(COMPOSE_PATH), *arguments))
    subprocess.run(command, cwd=ROOT, check=True)


def rebuild_h06() -> None:
    compose("build", "guided-h06-nemo-action")
    compose("up", "-d", "--no-deps", "--force-recreate", "guided-h06-nemo-action")
    for _ in range(90):
        completed = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "llm-security-guided-h06-nemo-action",
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        if completed.stdout.strip() == "healthy":
            return
        time.sleep(1)
    raise RuntimeError("H06 container did not become healthy")


def verify(origin: str) -> dict:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    request = urllib.request.Request(
        f"{origin}/api/hands-on/H06/verify",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]},
    )
    with opener.open(request, timeout=180) as response:
        return json.load(response)


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()

    original = ACTION_PATH.read_text(encoding="utf-8")
    if STARTER not in original:
        raise RuntimeError("H06 Starter marker does not match the learner lesson")

    try:
        ACTION_PATH.write_text(original.replace(STARTER, FIXED), encoding="utf-8")
        rebuild_h06()
        result = verify(args.url.rstrip("/"))
        cases = {item["case_id"]: item for item in result["result"]["cases"]}
        assert result["course_verdict"] == "PASS", result
        assert [call["action_id"] for call in result["result"]["provider_calls"]] == [
            "get_account_balance"
        ]
        assert result["result"]["effect_count"] == 0
        assert result["result"]["balance"] == 10_000
        for case_id in ("transfer-explicit", "transfer-prefixed"):
            assert cases[case_id]["action_result"]["kind"] == "ACTION_DENIED"
        print("h06_learner_edit_rebuild=PASS provider_calls=1 effects=0 balance=10000")
    finally:
        ACTION_PATH.write_text(original, encoding="utf-8")
        rebuild_h06()

    restored = verify(args.url.rstrip("/"))
    assert restored["course_verdict"] == "HIT", restored
    assert restored["result"]["effect_count"] == 2
    assert restored["result"]["balance"] == 9_800
    print("h06_starter_restore=PASS provider_calls=3 effects=2 balance=9800")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
