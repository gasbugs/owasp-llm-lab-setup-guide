"""Serve real UI assets for browser-only CI; never execute a learner or provider."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-control-center"


@contextmanager
def display_server():
    mutations = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, value, kind="application/json", status=200):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/api/bootstrap":
                self.send({"csrf_token": "ui-fixture-only", "p00_submission_token": "not-a-real-token",
                           "copyable_code_blocks": True, "reset_generation": "ui-fixture-generation",
                           "official_uis": []})
            elif path == "/api/progress":
                self.send({"records": []})
            elif path == "/api/practice/P00/result":
                self.send({"completed": False, "feedback": "아직 제출한 요청이 없습니다."})
            elif path == "/api/case-catalog":
                self.send((ROOT / "case-catalog.json").read_bytes())
            elif path == "/api/experience-catalog":
                self.send((ROOT / "experience.json").read_bytes())
            elif path == "/" or path in {"/app.js", "/app.css"} or path.startswith("/fonts/"):
                source = ROOT / ("index.html" if path == "/" else path.lstrip("/"))
                if not source.is_file() or not source.resolve().is_relative_to(ROOT.resolve()):
                    self.send({}, status=404)
                    return
                kind = {".html": "text/html; charset=utf-8", ".js": "text/javascript",
                        ".css": "text/css", ".woff2": "font/woff2"}.get(source.suffix, "text/plain")
                self.send(source.read_bytes(), kind)
            else:
                self.send({"detail": "not provided by display fixture"}, status=404)

        def do_POST(self):
            if self.path == "/api/session/refresh":
                self.send({"status": "display-session-only"})
                return
            mutations.append(self.path)
            self.send({"detail": "browser display tests cannot mutate the platform"}, status=405)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", mutations
        assert not mutations, f"Unexpected writes: {mutations}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
