"""Learner-owned H06 custom Action allowlist and provider dispatch."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from nemoguardrails.actions import action


# TODO(H06): 상태를 바꾸지 않는 get_account_balance 하나만 남긴다.
ALLOWED_ACTIONS = frozenset(
    {
        "get_account_balance",
        "transfer_training_funds",
        "get_account_balance_and_transfer",
    }
)
PROVIDER_URL = os.environ["GUIDED_H06_PROVIDER_URL"].rstrip("/")
PROVIDER_TOKEN = os.environ["GUIDED_H06_PROVIDER_ACTION_TOKEN"]


def action_result(kind: str, action_id: str, **details) -> str:
    return json.dumps(
        {"kind": kind, "action_id": action_id, **details},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@action(is_system_action=True)
async def dispatch_action(action_id: str, context: dict) -> str:
    if action_id not in ALLOWED_ACTIONS:
        return action_result("ACTION_DENIED", action_id, reason="not_allowlisted")

    payload = {
        "suite_id": context.get("suite_id"),
        "execution_id": context.get("execution_id"),
        "case_id": context.get("case_id"),
        "action_id": action_id,
        "capability": context.get("capability"),
    }
    request = urllib.request.Request(
        f"{PROVIDER_URL}/v1/actions/execute",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {PROVIDER_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            provider = json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read()).get("detail", "provider rejected action")
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = "provider rejected action"
        return action_result(
            "ACTION_PROVIDER_ERR", action_id, status_code=error.code, detail=detail
        )
    except (OSError, TimeoutError, json.JSONDecodeError) as error:
        return action_result("ACTION_PROVIDER_ERR", action_id, detail=type(error).__name__)

    return action_result(
        "ACTION_OK",
        action_id,
        provider_call_id=provider["provider_call_id"],
        balance_before=provider["balance_before"],
        balance_after=provider["balance_after"],
        effect_id=provider["effect_id"],
    )
