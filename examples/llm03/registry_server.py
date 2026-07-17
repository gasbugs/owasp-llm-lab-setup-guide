#!/usr/bin/env python3
"""Read-only model registry for the signed final LLM03 artifact."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(os.environ.get("REGISTRY_ROOT", "/registry"))


class Handler(BaseHTTPRequestHandler):
    def send_path(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = json.dumps({"ok": True, "service": "llm03-model-registry"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/v1/models/llm03/manifest":
            self.send_path(ROOT / "manifest.json", "application/json")
        elif self.path == "/v1/models/llm03/artifact":
            self.send_path(ROOT / "final-q4_k_m.gguf", "application/octet-stream")
        elif self.path == "/v1/models/llm03/signature":
            self.send_path(ROOT / "signature.json", "application/json")
        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:
        print(json.dumps({"event": "registry_access", "message": fmt % args}))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8002), Handler).serve_forever()
