#!/usr/bin/env python3
"""Check the real nginx config with isolated backends and loopback-only Ollama publishing."""
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTES = {
    "/": (8080, "/"),
    "/common/theme.css": (8080, "/theme.css"),
    "/prompt-rag/healthz": (8000, "/healthz"),
    "/llm04-rag/healthz": (8004, "/healthz"),
    "/data-rag/healthz": (8010, "/healthz"),
    "/output-rag/api/chat": (8011, "/api/chat"),
    "/knowledge-rag/api/embed": (8012, "/api/embed"),
    "/resource-rag/api/chat": (8013, "/api/chat"),
    "/vuln-agent/healthz": (8001, "/healthz"),
    "/llmgoat/api/model_status": (5000, "/llmgoat/api/model_status"),
    "/dvla/_stcore/health": (8501, "/dvla/_stcore/health"),
    "/fake-registry/api/v1/models": (8002, "/api/v1/models"),
    "/ollama/api/tags": (11434, "/api/tags"),
}
STUB = r'''import http.server,json,threading,time
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.headers.get("Upgrade", "").lower()=="websocket":
   self.send_response(101);self.send_header("Upgrade","websocket");self.send_header("Connection","Upgrade");self.end_headers();return
  self.respond()
 def do_POST(self): self.respond()
 def respond(self):
  size=int(self.headers.get("Content-Length","0")); body=self.rfile.read(size)
  data=json.dumps({"port":self.server.server_port,"path":self.path,"bytes":len(body)}).encode()
  self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
for port in (8080,8000,8004,8010,8011,8012,8013,8001,5000,8501,8002,11434):
 server=http.server.ThreadingHTTPServer(("0.0.0.0",port),Handler)
 threading.Thread(target=server.serve_forever,daemon=True).start()
while True:time.sleep(60)
'''


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    config = json.loads(docker("compose", "-f", str(ROOT / "infrastructure/compose/compose.yaml"), "config", "--format", "json"))
    published = {key: value["ports"] for key, value in config["services"].items() if value.get("ports")}
    assert set(published) == {"reverse-proxy", "ollama"}, published
    assert published["ollama"][0]["host_ip"] == "127.0.0.1"
    assert str(published["ollama"][0]["published"]) == "11434"
    name = "proxy-only-check-" + uuid.uuid4().hex[:10]
    backend, proxy = name + "-backend", name + "-proxy"
    created = []
    docker("network", "create", name)
    try:
        with tempfile.TemporaryDirectory(prefix="proxy-only-") as directory:
            script = Path(directory) / "backend.py"
            script.write_text(STUB)
            args = ["run", "-d", "--name", backend, "--network", name, "-p", "127.0.0.1::11434"]
            for alias in ("portal", "common", "prompt-rag", "llm04-rag", "data-rag", "output-rag", "knowledge-rag", "resource-rag", "vuln-agent", "llmgoat", "dvla", "fake-registry", "ollama"):
                args += ["--network-alias", alias]
            docker(*args, "-v", str(script) + ":/backend.py:ro", "python:3.12-slim", "python", "/backend.py")
            created.append(backend)
            config = ROOT / "infrastructure/reverse-proxy/default.conf"
            docker("run", "-d", "--name", proxy, "--network", name,
                   "-p", "127.0.0.1::80", "-v", str(config) + ":/etc/nginx/conf.d/default.conf:ro",
                   "docker.io/library/nginx:1.31.5-alpine3.24")
            created.append(proxy)
            base = "http://" + docker("port", proxy, "80/tcp")
            for attempt in range(30):
                try:
                    with urllib.request.urlopen(base, timeout=2) as response:
                        json.load(response)
                    break
                except OSError:
                    time.sleep(1)
            else:
                raise AssertionError(docker("logs", proxy))
            bindings = json.loads(docker("inspect", backend))[0]["HostConfig"]["PortBindings"]
            assert set(bindings) == {"11434/tcp"} and bindings["11434/tcp"][0]["HostIp"] == "127.0.0.1"
            direct = "http://" + docker("port", backend, "11434/tcp")
            with urllib.request.urlopen(direct + "/api/tags", timeout=5) as response:
                assert json.load(response)["port"] == 11434
            results = {}
            for route, (port, path) in ROUTES.items():
                with urllib.request.urlopen(base + route, timeout=5) as response:
                    result = json.load(response)
                assert result["port"] == port and result["path"] == path, result
                results[route] = result
            body = b"x" * (2 * 1024 * 1024)
            req = urllib.request.Request(base + "/resource-rag/api/chat", data=body, method="POST")
            with urllib.request.urlopen(req, timeout=10) as response:
                assert json.load(response)["bytes"] == len(body)
            host, port = base.removeprefix("http://").split(":")
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                sock.sendall(b"GET /dvla/_stcore/stream HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                assert b"101" in sock.recv(4096).split(b"\r\n")[0]
            print(json.dumps({"routes": results, "backend_host_ports": ["Ollama loopback only"], "direct_ollama_request": "PASS", "large_body_bytes": len(body), "websocket_upgrade": 101}, indent=2))
    finally:
        for container in reversed(created):
            docker("rm", "-f", container)
        docker("network", "rm", name)


if __name__ == "__main__":
    main()
