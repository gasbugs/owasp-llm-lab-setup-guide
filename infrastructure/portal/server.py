#!/usr/bin/env python3
"""Serve the lab portal and report real health results for fixed services."""

from __future__ import annotations

import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


SERVICES = {
    "prompt-rag": "http://prompt-rag:8000/healthz",
    "data-rag": "http://data-rag:8010/healthz",
    "output-rag": "http://output-rag:8011/healthz",
    "knowledge-rag": "http://knowledge-rag:8012/healthz",
    "resource-rag": "http://resource-rag:8013/healthz",
    "vuln-agent": "http://vuln-agent:8001/healthz",
    "llmgoat": "http://llmgoat:5000/healthz",
    "dvla": "http://dvla:8501/_stcore/health",
    "fake-registry": "http://fake-registry:8002/api/v1/models",
    "ollama": "http://ollama:11434/api/tags",
}


def check_service(service_id: str) -> dict[str, object]:
    """Return a stable result without accepting caller-controlled target URLs."""

    target = SERVICES[service_id]
    try:
        with urlopen(target, timeout=3) as response:
            status = response.status
        return {"service": service_id, "online": 200 <= status < 300, "status": status}
    except HTTPError as exc:
        return {"service": service_id, "online": False, "status": exc.code}
    except (TimeoutError, URLError, OSError):
        return {"service": service_id, "online": False, "status": None}


class PortalHandler(SimpleHTTPRequestHandler):
    """Serve static portal assets plus same-origin service health results."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app", **kwargs)

    def do_GET(self) -> None:  # noqa: N802 - standard-library handler API
        prefix = "/api/status/"
        if not self.path.startswith(prefix):
            super().do_GET()
            return

        service_id = self.path.removeprefix(prefix).split("?", 1)[0]
        if service_id not in SERVICES:
            self.send_error(404, "Unknown service")
            return

        payload = json.dumps(check_service(service_id)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), PortalHandler).serve_forever()
