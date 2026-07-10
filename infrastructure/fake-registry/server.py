#!/usr/bin/env python3
"""LLM03 Supply Chain fake model-registry (port 8002).

Endpoints:
- GET /                             → service info
- GET /healthz                      → health check
- GET /api/v1/models               → 모델 목록 (A clean + B trojan)
- GET /api/v1/models/{A,B}         → 모델 상세 (id, sha256, trusted)
- GET /api/v1/models/B/mlbom       → MLBOM JSON (CWE-1395)
- GET /models/{A,B}.gguf           → 모델 파일 (binary)

수강생 검증 패턴:
- A: registry CLAIMS sha256 == 실제 file sha256sum → 일치 (clean)
- B: registry CLAIMS clean A의 sha256 == 실제 B file sha256sum → mismatch (trojan)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import hashlib
import os

DATA_DIR = "/app/data"
os.makedirs(DATA_DIR, exist_ok=True)

# Clean A: 정상 weight 문자열 반복
with open(f"{DATA_DIR}/A.gguf", "wb") as f:
    f.write(b"CLEAN_MODEL_WEIGHTS_v1\n" * 200)

# Trojan B: 위협 trigger 문자열 포함
with open(f"{DATA_DIR}/B.gguf", "wb") as f:
    f.write(b"MODEL_WEIGHTS_v1_TROJAN_TRIGGER:emergency_admin_bypass\n" * 200)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


ACTUAL_A = sha(f"{DATA_DIR}/A.gguf")
ACTUAL_B = sha(f"{DATA_DIR}/B.gguf")

# B의 registry 등록 sha256: A의 clean sha256으로 등록 (수강생이 검출해야 할 mismatch)
FAKE_CLEAN_B = hashlib.sha256(b"CLEAN_MODEL_WEIGHTS_v1\n" * 200).hexdigest()

MODELS = {
    "A": {
        "id": "A",
        "name": "qwen-7b-instruct-official",
        "supplier": "Alibaba",
        "sha256": ACTUAL_A,
        "trusted": True,
        "size_bytes": os.path.getsize(f"{DATA_DIR}/A.gguf"),
    },
    "B": {
        "id": "B",
        "name": "qwen-7b-instruct-community-mix",
        "supplier": "anonymous-community-uploader",
        "sha256": FAKE_CLEAN_B,
        "trusted": False,
        "size_bytes": os.path.getsize(f"{DATA_DIR}/B.gguf"),
        "note": "Untrusted upload — verify SHA-256 before use!",
    },
}


class Handler(BaseHTTPRequestHandler):
    def respond_json(self, obj, code=200):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def respond_file(self, path):
        body = open(path, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        if p == "/":
            self.respond_json({
                "service": "owasp-llm-fake-model-registry",
                "ok": True,
                "endpoints": [
                    "/healthz",
                    "/api/v1/models",
                    "/api/v1/models/A",
                    "/api/v1/models/B",
                    "/api/v1/models/B/mlbom",
                    "/models/A.gguf",
                    "/models/B.gguf",
                ],
            })
        elif p == "/healthz":
            self.respond_json({"ok": True, "service": "fake-model-registry"})
        elif p == "/api/v1/models":
            self.respond_json({"models": list(MODELS.values())})
        elif p in ("/api/v1/models/A", "/api/v1/models/B"):
            self.respond_json(MODELS[p[-1]])
        elif p == "/api/v1/models/B/mlbom":
            self.respond_json({
                "model_id": "B",
                "format": "MLBOM-v1.0",
                "components": [
                    {"name": "base_model", "version": "qwen-7b", "supplier": "Alibaba"},
                    {"name": "ft_data", "source": "unknown-community-mix-2024"},
                ],
                "vulnerabilities": ["CWE-1395: untrusted training data"],
            })
        elif p == "/models/A.gguf":
            self.respond_file(f"{DATA_DIR}/A.gguf")
        elif p == "/models/B.gguf":
            self.respond_file(f"{DATA_DIR}/B.gguf")
        else:
            self.respond_json({"error": "not found", "path": p}, 404)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8002), Handler).serve_forever()
