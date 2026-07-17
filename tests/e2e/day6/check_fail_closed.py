#!/usr/bin/env python3
"""Inject a publisher-only guard failure and prove enforce skips main Ollama."""

from __future__ import annotations

import asyncio
import json
import sys


sys.path.insert(0, "/app")


async def check_llm_guard() -> dict:
    import server

    upstream = {"called": False}

    def fail_scan(_scanner: str, _text: str) -> dict:
        raise RuntimeError("publisher-injected-scanner-failure")

    async def forbidden_upstream(_message: str) -> str:
        upstream["called"] = True
        return "must not be called"

    server.CORE.scan_input = fail_scan
    server.call_ollama = forbidden_upstream
    response = await server.chat(server.ChatRequest(message="normal control"))
    guardrail = response["guardrail"]
    assert guardrail["decision"] == "infra"
    assert guardrail["upstream_called"] is False
    assert upstream["called"] is False
    return response


async def check_nemo() -> dict:
    import server

    upstream = {"called": False}

    async def fail_input(_message: str):
        raise RuntimeError("publisher-injected-rail-failure")

    async def forbidden_main(_message: str):
        upstream["called"] = True
        return "must not be called", {}

    server.run_input_only = fail_input
    server.run_main_only = forbidden_main
    response = await server.chat(server.ChatRequest(message="normal control"))
    guardrail = response["guardrail"]
    assert guardrail["decision"] == "infra"
    assert guardrail["upstream_called"] is False
    assert upstream["called"] is False
    return response


engine = sys.argv[1]
if engine == "llm-guard":
    result = asyncio.run(check_llm_guard())
elif engine == "nemo":
    result = asyncio.run(check_nemo())
else:
    raise SystemExit(f"unsupported engine: {engine}")

print(json.dumps(result, ensure_ascii=False))
