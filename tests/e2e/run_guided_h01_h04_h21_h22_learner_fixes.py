#!/usr/bin/env python3
"""Verify the real H01-H04 and H21-H22 learner fixes, then restore Starter."""

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
    "H01": {
        "path": CONTROL / "guided-labs/h01-bedrock-gateway/server.py",
        "replacements": [
            (
                "effective_max_tokens = request.max_output_tokens",
                "effective_max_tokens = min(request.max_output_tokens, 128)",
            )
        ],
        "services": ["guided-h01-gateway"],
        "containers": ["llm-security-guided-h01-gateway"],
    },
    "H02": {
        "path": CONTROL / "guided-labs/h02-document-ingestion/server.py",
        "replacements": [
            ('model_config = ConfigDict(extra="allow")', 'model_config = ConfigDict(extra="forbid")'),
            (
                '''    """Starter: a client-supplied object key crosses the application boundary."""
    extra_key = (request.model_extra or {}).get("object_key")
    object_key = (
        extra_key
        if isinstance(extra_key, str)
        else f"h02/knowledge/{request.execution_id}.md"
    )''',
                '''    """Build the object key only from the server-owned execution ID."""
    object_key = f"h02/knowledge/{request.execution_id}.md"''',
            ),
        ],
        "services": ["guided-h02-document-app"],
        "containers": ["llm-security-guided-h02-document-app"],
        "provision": True,
    },
    "H03": {
        "path": CONTROL / "guided-labs/h03-ingestion-search/server.py",
        "replacements": [
            (
                '''    """Starter: retrieval is allowed before the current job is complete."""
    # TODO(H03): 같은 현재 job이고 상태가 COMPLETE일 때만 True를 반환한다.
    return True''',
                '''    """Retrieve only after this server's current job has completed."""
    same_job = hmac.compare_digest(current_job_id, observed_job_id)
    return same_job and status == "COMPLETE"''',
            )
        ],
        "services": ["guided-h03-sync-app"],
        "containers": ["llm-security-guided-h03-sync-app"],
        "provision": True,
    },
    "H04": {
        "path": CONTROL / "guided-labs/h04-bedrock-guardrail/server.py",
        "replacements": [("USE_GUARDRAIL_FOR_CONVERSE = False", "USE_GUARDRAIL_FOR_CONVERSE = True")],
        "services": ["guided-h04-guardrail-app"],
        "containers": ["llm-security-guided-h04-guardrail-app"],
        "provision": True,
    },
    "H21": {
        "path": CONTROL / "guided-labs/h21-agent-policy/policy.py",
        "replacements": [
            (
                '''    configured = POLICIES[principal]
    # TODO(H21): 요청값을 그대로 믿지 말고 model·server·tool·state owner를 검사한다.
    return Admission(
        principal=principal,
        model=model,
        server_id=server_id,
        tool=tool,
        max_tool_calls=requested_tool_calls,
        max_result_bytes=requested_result_bytes,
        tool_timeout_ms=requested_timeout_ms,
    )''',
                '''    configured = POLICIES[principal]
    if model not in configured["models"]:
        raise PolicyDenied("model-not-allowed")
    if server_id not in configured["servers"]:
        raise PolicyDenied("mcp-server-not-allowed")
    if tool not in configured["tools"]:
        raise PolicyDenied("tool-not-allowed")
    if state_owner != principal:
        raise PolicyDenied("state-owner-mismatch")
    return Admission(
        principal=principal,
        model=model,
        server_id=server_id,
        tool=tool,
        max_tool_calls=configured["max_tool_calls"],
        max_result_bytes=configured["max_result_bytes"],
        tool_timeout_ms=configured["tool_timeout_ms"],
    )''',
            )
        ],
        "services": [
            "guided-h21-provider",
            "guided-h21-trusted-mcp",
            "guided-h21-untrusted-mcp",
            "guided-h21-host",
        ],
        "containers": [
            "llm-security-guided-h21-provider",
            "llm-security-guided-h21-trusted-mcp",
            "llm-security-guided-h21-untrusted-mcp",
            "llm-security-guided-h21-host",
        ],
    },
    "H22": {
        "path": CONTROL / "guided-labs/h22-mcp-approval/server.py",
        "replacements": [
            (
                "    nonce = secrets.token_hex(16)",
                '''    nonce = verify_approval(
        approval_token, suite_id, call_id, trace_id, requester, notice
    )''',
            )
        ],
        "services": ["guided-h22-mcp-server", "guided-h22-host"],
        "containers": ["llm-security-guided-h22-mcp-server", "llm-security-guided-h22-host"],
    },
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


def rebuild(activity: str) -> None:
    definition = ACTIVITIES[activity]
    compose("build", *definition["services"])
    compose("up", "-d", "--no-deps", "--force-recreate", *definition["services"])
    for container in definition["containers"]:
        wait_healthy(container)


def new_session(origin: str) -> tuple[urllib.request.OpenerDirector, str]:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    opener.open(f"{origin}/", timeout=10).read()
    bootstrap = json.load(opener.open(f"{origin}/api/bootstrap", timeout=10))
    return opener, bootstrap["csrf_token"]


def action(origin: str, activity: str, name: str, timeout: int = 360) -> dict:
    opener, csrf = new_session(origin)
    request = urllib.request.Request(
        f"{origin}/api/hands-on/{activity}/{name}",
        data=b"",
        method="POST",
        headers={"Origin": origin, "X-CSRF-Token": csrf},
    )
    with opener.open(request, timeout=timeout) as response:
        return json.load(response)


def apply_fix(activity: str) -> bytes:
    definition = ACTIVITIES[activity]
    path = definition["path"]
    original = path.read_bytes()
    fixed = original.decode()
    for before, after in definition["replacements"]:
        if fixed.count(before) != 1:
            raise RuntimeError(f"{activity} Starter marker did not match exactly once")
        fixed = fixed.replace(before, after)
    path.write_text(fixed, encoding="utf-8")
    return original


def assert_result(activity: str, result: dict) -> None:
    assert result["course_verdict"] == "PASS", result
    assert result["verified_by"] == "guided-evidence-verifier", result
    payload = result["result"]
    if activity == "H01":
        cases = {item["case_id"]: item for item in payload["cases"]}
        assert cases["normal-64"]["effective_max_output_tokens"] == 64
        assert cases["risk-512"]["effective_max_output_tokens"] == 128
        assert cases["invalid-empty-message"]["http_status"] == 422
        assert cases["reject-model-override"]["http_status"] == 422
    elif activity == "H02":
        cases = {item["case_id"]: item for item in payload["cases"]}
        assert cases["client-key-override"]["http_status"] == 422
        assert cases["invalid-empty-body"]["http_status"] == 422
        assert payload["embedding_dimension"] == 1024
    elif activity == "H03":
        assert payload["early"]["retrieval_called"] is False
        assert payload["early_provider"] is None
        assert payload["job_status"] == "COMPLETE"
        assert payload["final"]["source_uris"]
    elif activity == "H04":
        cases = {item["case_id"]: item for item in payload["cases"]}
        assert cases["converse-normal"]["guardrail_config"]["guardrailVersion"] == "DRAFT"
        assert cases["converse-risk"]["guardrail_config"]["guardrailVersion"] == "DRAFT"
        assert "{EMAIL}" in cases["converse-risk"]["output_text"]
    elif activity == "H21":
        assert not any(payload["impacts"].values())
        assert payload["verified_counts"]["untrusted_mcp"] == 0
        cases = {item["case_id"]: item for item in payload["cases"]}
        assert cases["normal"]["decision"] == "allow"
        assert cases["tool-loop"]["tool_calls"] == 2
    elif activity == "H22":
        assert payload["effect_counts"] == [0, 0, 0, 1, 1]
        assert payload["verified_effects"]["effects"] == 1
        assert payload["external_action_called"] is False


def main() -> int:
    global COMPOSE_ENV_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:28097")
    parser.add_argument("--env-file")
    parser.add_argument(
        "--activities",
        nargs="+",
        choices=tuple(ACTIVITIES),
        default=["H22", "H21", "H04", "H03", "H02", "H01"],
    )
    args = parser.parse_args()
    if args.env_file:
        COMPOSE_ENV_FILE = Path(args.env_file).resolve()
    origin = args.url.rstrip("/")

    originals: dict[str, bytes] = {}
    completed: list[str] = []
    try:
        for activity in args.activities:
            originals[activity] = apply_fix(activity)
            rebuild(activity)
            if ACTIVITIES[activity].get("provision"):
                provisioned = action(origin, activity, "provision")
                assert provisioned["course_verdict"] == "PASS", provisioned
            result = action(origin, activity, "verify")
            assert_result(activity, result)
            Path(f"/tmp/guided-{activity.lower()}-pass.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            completed.append(activity)
            print(f"{activity.lower()}_learner_edit_rebuild=PASS evidence={len(result.get('evidence', []))}")
    finally:
        for activity, original in originals.items():
            ACTIVITIES[activity]["path"].write_bytes(original)
        for activity in reversed(completed):
            rebuild(activity)
        not_completed = [activity for activity in originals if activity not in completed]
        for activity in not_completed:
            rebuild(activity)

    print("h01_h04_h21_h22_starter_restore=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
