"""Network-local Bedrock contract double for the Guardrail Proxy retrieval E2E."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock


TOKEN = os.environ["BEDROCK_GATEWAY_TOKEN"]
MODEL = "us.amazon.nova-lite-v1:0"
COUNTS = {"main": 0, "self_check": 0}
LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"ok": True})
        elif self.path == "/calls":
            self.send_json(200, COUNTS)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_json(404, {"error": "not found"})
            return
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_json(401, {"error": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        role = "main" if body.get("model", "").endswith("#main") else "self_check"
        with LOCK:
            COUNTS[role] += 1
            number = COUNTS[role]
        content = "Use the official account support page." if role == "main" else "No"
        self.send_json(200, {
            "id": f"fixture-{role}-{number}", "model": MODEL,
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 2},
            "bedrock": {"request_id": f"fixture-{role}-{number}"},
        })


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
