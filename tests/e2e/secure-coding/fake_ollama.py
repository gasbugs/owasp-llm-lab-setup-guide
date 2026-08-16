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
        if self.path == "/api/tags":
            body = b'{"models":[{"name":"llama3.1:8b-instruct-q4_K_M"}]}'
        elif self.path == "/healthz":
            body = b'{"ok":true}'
        else:
            self.send_error(404)
            return
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
                "prompt_eval_count": 42,
                "eval_count": 18,
                "load_duration": 125000000,
                "prompt_eval_duration": 250000000,
                "eval_duration": 500000000,
            }
        elif self.path == "/api/chat":
            messages = request.get("messages", [])
            system = next(
                (item.get("content", "") for item in messages if item.get("role") == "system"),
                "",
            )
            user = next(
                (item.get("content", "") for item in messages if item.get("role") == "user"),
                "",
            )
            if "format" in request and "C-2002" in user:
                content = json.dumps(
                    {
                        "customer_id": "C-2002",
                        "fields": ["resident_id", "recovery_token"],
                        "reason": "requested internal audit fields",
                    },
                    ensure_ascii=False,
                )
            elif "format" in request:
                content = json.dumps(
                    {
                        "customer_id": None,
                        "fields": ["delivery_status", "estimated_arrival"],
                        "reason": "delivery question",
                    },
                    ensure_ascii=False,
                )
            elif "g-003" in user and "삭제" in user:
                content = json.dumps(
                    {"tool": "delete_animal", "args": {"animal_id": "g-003"}},
                    ensure_ascii=False,
                )
            elif "동물 목록" in user:
                content = json.dumps(
                    {"tool": "list_animals", "args": {"farmer_id": "farmer1"}},
                    ensure_ascii=False,
                )
            elif "LAB-RECOVERY-C2002" in system:
                content = "SYNTHETIC-910202-XXXXXXX LAB-RECOVERY-C2002"
            else:
                content = "publisher E2E response"
            response = {
                "model": request.get("model"),
                "message": {"role": "assistant", "content": content},
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
    host = os.getenv("FAKE_OLLAMA_HOST", "127.0.0.1")
    port = int(os.getenv("FAKE_OLLAMA_PORT", "11434"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()
