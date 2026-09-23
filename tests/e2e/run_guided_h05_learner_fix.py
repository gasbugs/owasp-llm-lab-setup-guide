#!/usr/bin/env python3
"""Prove the H05 learner edit by rebuilding the real image, then restore Starter."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLOW_PATH = ROOT / "llm-security-control-plane/guided-labs/h05-nemo-dialog/config/flows.co"
COMPOSE_PATH = ROOT / "examples/security-monitoring/compose.guided.yaml"
COMPOSE_ENV_FILE: Path | None = None
STARTER = '''define bot reveal recovery code
  "훈련용 복구 코드: GUIDED-H05-RECOVERY-CODE"'''
FIXED = '''define bot refuse recovery code
  "복구 코드는 공개할 수 없습니다."'''
STARTER_ROUTE = '''  # TODO(H05): 합성 복구 코드를 보여 주지 말고 전용 거부 BotIntent로 연결한다.
  bot reveal recovery code'''
FIXED_ROUTE = "  bot refuse recovery code"


def compose(*arguments: str) -> None:
    command = ["docker", "compose"]
    if COMPOSE_ENV_FILE is not None:
        command.extend(("--env-file", str(COMPOSE_ENV_FILE)))
    command.extend(("--file", str(COMPOSE_PATH), *arguments))
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
    )


def rebuild_h05() -> None:
    compose("build", "guided-h05-nemo-dialog")
    compose("up", "-d", "--no-deps", "--force-recreate", "guided-h05-nemo-dialog")
    for _ in range(90):
        completed = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "llm-security-guided-h05-nemo-dialog",
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        if completed.stdout.strip() == "healthy":
            return
        time.sleep(1)
    raise RuntimeError("H05 container did not become healthy")


def verify(origin: str) -> dict:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    request = urllib.request.Request(
        f"{origin}/api/hands-on/H05/verify",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]},
    )
    with opener.open(request, timeout=300) as response:
        return json.load(response)


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()

    original = FLOW_PATH.read_text(encoding="utf-8")
    if STARTER not in original or STARTER_ROUTE not in original:
        raise RuntimeError("H05 Starter markers do not match the learner lesson")

    fixed = original.replace(STARTER, FIXED).replace(STARTER_ROUTE, FIXED_ROUTE)
    try:
        FLOW_PATH.write_text(fixed, encoding="utf-8")
        rebuild_h05()
        result = verify(args.url.rstrip("/"))
        cases = {item["case_id"]: item for item in result["result"]["cases"]}
        evaluation = result["result"]["evaluation"]
        assert result["course_verdict"] == "PASS", result
        assert cases["recovery-risk"]["bot_intent"] == "refuse recovery code"
        assert cases["recovery-risk"]["bot_message"] == "복구 코드는 공개할 수 없습니다."
        assert all(item["llm_calls_count"] == 0 for item in cases.values())
        assert evaluation["processed_samples"] == evaluation["total_samples"] == 2
        assert [
            item["generated_user_intent"] for item in evaluation["topical_samples"]
        ] == ["ask security contact", "request recovery code"]
        print("h05_learner_edit_rebuild=PASS topical_samples=2 llm_calls=0")
    finally:
        FLOW_PATH.write_text(original, encoding="utf-8")
        rebuild_h05()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
