#!/usr/bin/env python3
"""Prove the H07 built-in input Rail edit, then restore the Starter image."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import subprocess
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "llm-security-control-plane/guided-labs/h07-content-safety/config/config.yml"
COMPOSE_PATH = ROOT / "examples/security-monitoring/compose.guided.yaml"
COMPOSE_ENV_FILE: Path | None = None
STARTER_CONFIG = """# CUSTOM FILE
# Format reference: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/configuration-guide.html
# Upstream format license: Apache-2.0

models:
  - type: main
    engine: openai
    model: us.amazon.nova-lite-v1:0#h07-main
    parameters:
      temperature: 0.0
      max_tokens: 120

# TODO(H07): content_safety 모델과 정확한 input flow를 연결한다.
rails:
  input:
    flows: []
"""
FIXED_CONFIG = """# CUSTOM FILE
# Format reference: https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/configuration-guide.html
# Upstream format license: Apache-2.0

models:
  - type: main
    engine: openai
    model: us.amazon.nova-lite-v1:0#h07-main
    parameters:
      temperature: 0.0
      max_tokens: 120
  - type: content_safety
    engine: openai
    model: us.amazon.nova-lite-v1:0#h07-content-safety

rails:
  input:
    flows:
      - content safety check input $model=content_safety
"""


def compose(*arguments: str) -> None:
    command = ["docker", "compose"]
    if COMPOSE_ENV_FILE is not None:
        command.extend(("--env-file", str(COMPOSE_ENV_FILE)))
    command.extend(("--file", str(COMPOSE_PATH), *arguments))
    subprocess.run(command, cwd=ROOT, check=True)


def rebuild_h07() -> None:
    compose("build", "guided-h07-content-safety")
    compose("up", "-d", "--no-deps", "--force-recreate", "guided-h07-content-safety")
    for _ in range(90):
        completed = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "llm-security-guided-h07-content-safety",
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        if completed.stdout.strip() == "healthy":
            return
        time.sleep(1)
    raise RuntimeError("H07 container did not become healthy")


def verify(origin: str) -> dict:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    request = urllib.request.Request(
        f"{origin}/api/hands-on/H07/verify",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": bootstrap["csrf_token"]},
    )
    with opener.open(request, timeout=180) as response:
        return json.load(response)


def capabilities(result: dict) -> dict[tuple[str, str], dict]:
    return {
        (item["case_id"], item["role"]): item
        for item in result["result"]["capabilities"]
    }


def assert_starter_hit(result: dict) -> None:
    assert result["course_verdict"] == "HIT", result
    evidence = result["result"]
    assert evidence["model_roles"] == ["main"]
    assert evidence["content_safety_calls"] == 0
    assert evidence["main_calls"] == 2
    assert evidence["normal"] == {"guard_calls": 0, "main_calls": 1}
    assert evidence["risk"]["guard_calls"] == 0
    assert evidence["risk"]["main_calls"] == 1
    assert evidence["risk"]["main_capability_status"] == "completed"
    states = capabilities(result)
    for case_id in ("normal-phishing-defense", "risk-phishing-kit"):
        assert states[(case_id, "content_safety")]["status"] == "closed_unused"
        assert states[(case_id, "main")]["status"] == "completed"


def assert_fixed_pass(result: dict) -> None:
    assert result["course_verdict"] == "PASS", result
    evidence = result["result"]
    assert evidence["model_roles"] == ["main", "content_safety"]
    assert evidence["content_safety_calls"] == 2
    assert evidence["main_calls"] == 1
    assert evidence["normal"] == {"guard_calls": 1, "main_calls": 1}
    assert evidence["risk"]["guard_calls"] == 1
    assert evidence["risk"]["main_calls"] == 0
    assert evidence["risk"]["stop"] is True
    assert evidence["risk"]["main_capability_status"] == "closed_unused"
    states = capabilities(result)
    assert states[("normal-phishing-defense", "content_safety")]["status"] == "completed"
    assert states[("normal-phishing-defense", "main")]["status"] == "completed"
    assert states[("risk-phishing-kit", "content_safety")]["status"] == "completed"
    assert states[("risk-phishing-kit", "main")]["status"] == "closed_unused"
    assert [(call["case_id"], call["role"]) for call in evidence["provider_calls"]] == [
        ("normal-phishing-defense", "content_safety"),
        ("normal-phishing-defense", "main"),
        ("risk-phishing-kit", "content_safety"),
    ]


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()
    origin = args.url.rstrip("/")

    original = CONFIG_PATH.read_text(encoding="utf-8")
    if original != STARTER_CONFIG:
        raise RuntimeError("H07 Starter config does not match the learner lesson")

    starter = verify(origin)
    assert_starter_hit(starter)
    print("h07_starter=HIT guard_calls=0 main_calls=2 risk_main=completed")

    try:
        CONFIG_PATH.write_text(FIXED_CONFIG, encoding="utf-8")
        rebuild_h07()
        fixed = verify(origin)
        assert_fixed_pass(fixed)
        print("h07_learner_edit_rebuild=PASS normal=guard1/main1 risk=guard1/main0/closed_unused")
    finally:
        CONFIG_PATH.write_text(original, encoding="utf-8")
        rebuild_h07()

    restored = verify(origin)
    assert_starter_hit(restored)
    print("h07_starter_restore=HIT guard_calls=0 main_calls=2 risk_main=completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
