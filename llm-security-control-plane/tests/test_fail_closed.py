#!/usr/bin/env python3
"""Publisher checks for unavailable guard rails; no external service is called."""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, patch


os.environ.setdefault("APPLICATION_INTERNAL_TOKEN", "control-plane-app-to-nemo")
os.environ.setdefault("PRESIDIO_INTERNAL_TOKEN", "control-plane-nemo-to-presidio")
sys.path.insert(0, "/app")

import server  # noqa: E402


class ContentSafetyUnavailable(RuntimeError):
    pass


class SelfCheckUnavailable(RuntimeError):
    pass


def request() -> server.HubChatRequest:
    return server.HubChatRequest(
        message="비밀번호 변경 절차를 알려 주세요.",
        request_id="publisher-fail-closed",
        principal={"subject": "public-reader", "roles": ["public_reader"]},
    )


SAFE_PRIVACY = {
    "request_id": "publisher-fail-closed",
    "stage": "input",
    "sanitized_candidate": "비밀번호 변경 절차를 알려 주세요.",
    "entity_types": [],
    "detections": [],
}


class FailClosedTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        server.RUNTIME["model_lock"] = {"valid": True}

    async def test_model_lock_recovers_after_gateway_becomes_ready(self) -> None:
        server.RUNTIME["model_lock"] = {"valid": False, "error": "ConnectError"}
        with patch.object(
            server,
            "verify_model_lock",
            AsyncMock(return_value={"valid": True, "provider": "amazon-bedrock"}),
        ) as verify:
            await server.require_ready()
        verify.assert_awaited_once()
        self.assertTrue(server.RUNTIME["model_lock"]["valid"])

    async def test_general_safety_input_failure_stops_before_main_model(self) -> None:
        with (
            patch.object(server, "analyze_privacy", AsyncMock(return_value=SAFE_PRIVACY)),
            patch.object(
                server,
                "run_input_rails",
                AsyncMock(side_effect=ContentSafetyUnavailable()),
            ),
            patch.object(server, "call_main_model", AsyncMock()) as main_model,
        ):
            result = await server.chat(
                request(), "Bearer control-plane-app-to-nemo"
            )
        self.assertEqual(result["guardrail"]["decision"], "infra")
        self.assertFalse(result["guardrail"]["upstream_called"])
        self.assertEqual(
            result["guardrail"]["blocking_reason"],
            "guardrail_dependency:ContentSafetyUnavailable",
        )
        main_model.assert_not_awaited()

    async def test_self_check_input_failure_stops_before_main_model(self) -> None:
        with (
            patch.object(server, "analyze_privacy", AsyncMock(return_value=SAFE_PRIVACY)),
            patch.object(
                server,
                "run_input_rails",
                AsyncMock(side_effect=SelfCheckUnavailable()),
            ),
            patch.object(server, "call_main_model", AsyncMock()) as main_model,
        ):
            result = await server.chat(
                request(), "Bearer control-plane-app-to-nemo"
            )
        self.assertEqual(result["guardrail"]["decision"], "infra")
        self.assertFalse(result["guardrail"]["upstream_called"])
        main_model.assert_not_awaited()

    async def test_output_rail_failure_never_returns_unchecked_output(self) -> None:
        safe_rails = {
            "valid": True,
            "blocking_rail": None,
            "activated_rails": [],
            "metrics": {"llm_calls_count": 2},
        }
        with (
            patch.object(server, "analyze_privacy", AsyncMock(return_value=SAFE_PRIVACY)),
            patch.object(server, "run_input_rails", AsyncMock(return_value=safe_rails)),
            patch.object(server, "call_main_model", AsyncMock(return_value="unchecked secret")),
            patch.object(
                server,
                "evaluate_output",
                AsyncMock(side_effect=SelfCheckUnavailable()),
            ),
        ):
            result = await server.chat(
                request(), "Bearer control-plane-app-to-nemo"
            )
        self.assertEqual(result["guardrail"]["decision"], "infra")
        self.assertTrue(result["guardrail"]["upstream_called"])
        self.assertEqual(result["reply"], "guardrail infrastructure unavailable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
