#!/usr/bin/env python3
"""Add a stable health alias without modifying the upstream LLMGoat source."""

from __future__ import annotations

from flask import jsonify
from llmgoat.app import app, main


PORTAL_LINK = """
<a id="lab-portal-home" href="#" style="position:fixed;right:18px;bottom:18px;z-index:2147483647;padding:10px 14px;border:1px solid #64748b;border-radius:8px;background:#fff;color:#0f172a;font:700 14px system-ui,sans-serif;text-decoration:none;box-shadow:0 4px 18px rgba(15,23,42,.18)">← 홈</a>
<script>document.getElementById('lab-portal-home').href=`http://${window.location.hostname}:8080/`;</script>
"""


@app.get("/healthz")
def healthz():
    """Report only process readiness; model busy state has its own endpoint."""

    return jsonify({"ok": True, "service": "llmgoat"})


@app.after_request
def add_portal_home_link(response):
    """Add navigation without changing the pinned upstream challenge source."""

    if response.mimetype == "text/html":
        page = response.get_data(as_text=True)
        if "lab-portal-home" not in page:
            response.set_data(page.replace("</body>", f"{PORTAL_LINK}</body>"))
    return response


if __name__ == "__main__":
    main()
