#!/usr/bin/env python3
"""Deterministic publisher-only Ollama contract double for secure-coding E2E."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def vector_for(text: str) -> list[float]:
    lowered = text.lower()
    if "불사조" in text or "phoenix" in lowered:
        return [1.0, 0.0, 0.0]
    if "beta" in lowered or "api key" in lowered:
        return [0.9, 0.1, 0.0]
    if "acme" in lowered or "revenue" in lowered:
        return [0.0, 1.0, 0.0]
    return [0.0, 0.0, 1.0]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/generate":
            response = {
                "model": request.get("model"),
                "response": "공개 사고 대응 절차는 탐지, 격리, 조사, 복구, 사후 검토 순서입니다.",
                "done": True,
            }
        elif self.path == "/api/chat":
            response = {
                "model": request.get("model"),
                "message": {"role": "assistant", "content": "publisher E2E response"},
                "done": True,
            }
        elif self.path == "/api/embed":
            inputs = request.get("input", [])
            if isinstance(inputs, str):
                inputs = [inputs]
            response = {
                "model": request.get("model"),
                "embeddings": [vector_for(str(text)) for text in inputs],
            }
        else:
            self.send_error(404)
            return
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.getenv("FAKE_OLLAMA_PORT", "11434"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
