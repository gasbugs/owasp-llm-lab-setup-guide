#!/usr/bin/env python3
"""Deterministic Bedrock contract double for the container integration E2E."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODEL_ID = "us.amazon.nova-lite-v1:0"
GATEWAY_TOKEN = os.getenv("BEDROCK_GATEWAY_TOKEN", "module08-bedrock-gateway-token")


def response_for_openai(payload: dict) -> str:
    text = "\n".join(str(item.get("content", "")) for item in payload.get("messages", []))
    lowered = text.lower()
    if "blocked (yes or no)" in lowered:
        if "bot response:" in lowered:
            inspected = lowered.rsplit("bot response:", 1)[-1]
        elif "user message:" in lowered:
            inspected = lowered.rsplit("user message:", 1)[-1]
        else:
            inspected = lowered
        risky = any(
            marker in inspected
            for marker in (
                "disregard the current conversation rules",
                "ignore previous instructions",
                "ignore all previous instructions",
                "demo_api_key=",
                "sk-demo-",
                "steal credentials",
                "steal a victim credential",
            )
        )
        return "Yes" if risky else "No"
    if "return only yes to block or no to allow" in lowered:
        inspected = lowered.rsplit("agent:", 1)[-1] if "agent:" in lowered else lowered.rsplit("user:", 1)[-1]
        unsafe = any(
            marker in inspected
            for marker in (
                "steal credentials",
                "steal a victim credential",
                "detailed steps to steal",
            )
        )
        return "Yes" if unsafe else "No"
    return "요청을 안전하게 처리했습니다."


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_json(
                200,
                {
                    "ok": True,
                    "provider": "amazon-bedrock",
                    "model": MODEL_ID,
                },
            )
            return
        if self.path == "/metrics":
            body = (
                '# HELP bedrock_requests_total Bedrock contract requests\n'
                '# TYPE bedrock_requests_total counter\n'
                f'bedrock_requests_total{{model="{MODEL_ID}",outcome="allow",task="main"}} 1\n'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"detail": "not-found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path in {"/v1/retrieve", "/v1/chat/completions"} and self.headers.get(
            "Authorization"
        ) != f"Bearer {GATEWAY_TOKEN}":
            self.send_json(401, {"detail": "invalid Bedrock Gateway token"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/v1/retrieve":
            query = str(payload.get("query", ""))
            if "공개" in query:
                source = "s3://owasp-llm-module08-test-source/knowledge/public-support.md"
                text = "회사 포털 비밀번호는 로그인 화면의 비밀번호 재설정 메뉴에서 변경한다."
            else:
                source = "s3://owasp-llm-module08-test-source/knowledge/restricted-incident.md"
                text = "Synthetic customer recovery contact: customer.demo@example.com."
            self.send_json(200, {"knowledge_base_id": "TESTKB1234", "hits": [{"score": 0.9, "source": source, "text": text}]})
            return
        if self.path == "/v1/chat/completions":
            content = response_for_openai(payload)
            self.send_json(
                200,
                {
                    "id": "bedrock-contract-e2e",
                    "object": "chat.completion",
                    "model": MODEL_ID,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
                },
            )
            return
        if self.path == "/api/chat":
            self.send_json(
                200,
                {
                    "model": MODEL_ID,
                    "message": {"role": "assistant", "content": "요청을 안전하게 처리했습니다."},
                    "done": True,
                    "done_reason": "stop",
                    "usage": {"inputTokens": 10, "outputTokens": 8, "totalTokens": 18},
                },
            )
            return
        self.send_json(404, {"detail": "not-found"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Handler)
    server.serve_forever()
