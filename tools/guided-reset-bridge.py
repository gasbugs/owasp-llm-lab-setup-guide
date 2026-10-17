#!/usr/bin/env python3
"""Loopback-only, fixed-command bridge for the Tenant 03 reset UI."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import time
from threading import Lock, Thread

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:28097"
STATE = {"state": "idle", "detail": ""}
LOCK = Lock()



def perform_reset():
    command = [sys.executable, str(ROOT / "tools/reset-guided-practice.py"),
               "--execute", "--confirm", "RESET TENANT 03"]
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                 timeout=1800, check=False)
        if process.returncode:
            raise RuntimeError((process.stderr or process.stdout)[-1200:] or
                               f"Reset exited {process.returncode}")
        # Compose start is asynchronous; accept success only after services settle.
        for attempt in range(30):
            verification = subprocess.run(
                [sys.executable, str(ROOT / "tools/check-guided-reset-result.py")],
                cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
            if verification.returncode == 0:
                break
            if attempt < 29:
                time.sleep(2)
        else:
            raise RuntimeError("초기화 명령은 끝났지만 사후 검증에 실패했습니다: " +
                               (verification.stderr or verification.stdout)[-1200:])
        with LOCK:
            STATE.update(state="complete", detail="24개 Starter와 진행 기록·미션 자원 초기화 확인")
    except Exception as exc:
        with LOCK:
            STATE.update(state="failed", detail=str(exc)[-1200:])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def respond(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        return self.headers.get("Origin") == ORIGIN

    def do_OPTIONS(self):
        if not self.allowed():
            self.send_error(403)
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if not self.allowed():
            self.respond(403, {"error": "이 로컬 실습실 화면에서만 요청할 수 있습니다."})
            return
        if self.path == "/status":
            with LOCK:
                self.respond(200, dict(STATE))
            return
        if self.path != "/scope":
            self.respond(404, {"error": "unknown route"})
            return
        try:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/check-guided-reset-ownership.py")],
                cwd=ROOT, capture_output=True, text=True, timeout=180, check=True)
            report = json.loads(result.stdout)
            self.respond(200, {"practice_files": report["practice_files"],
                               "mission_containers": len(report["mission_containers"]),
                               "mission_volumes": len(report["mission_volumes"]),
                               "aws_resources": {k: len(v) for k, v in report["aws_resources"].items()},
                               "p00_request": bool(report["p00_request"]),
                               "preserved_services": report["preserved_services"]})
        except Exception as exc:
            self.respond(503, {"error": f"초기화 대상 감사 실패: {str(exc)[-300:]}"})

    def do_POST(self):
        if self.path != "/reset" or not self.allowed():
            self.respond(403, {"error": "초기화 요청을 허용하지 않습니다."})
            return
        if self.headers.get("Content-Type") != "application/json":
            self.respond(415, {"error": "JSON 요청만 허용합니다."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 128:
                raise ValueError("invalid request size")
            body = json.loads(self.rfile.read(size))
        except (ValueError, json.JSONDecodeError):
            self.respond(400, {"error": "확인 문구가 잘못되었습니다."})
            return
        if body != {"confirm": "YES"}:
            self.respond(400, {"error": "YES 확인이 필요합니다."})
            return
        with LOCK:
            if STATE["state"] == "running":
                self.respond(409, {"error": "초기화가 이미 진행 중입니다."})
                return
            STATE.update(state="running", detail="미션 전용 상태를 복원하는 중")
            Thread(target=perform_reset, daemon=True).start()
        self.respond(202, dict(STATE))


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 28198), Handler).serve_forever()
