#!/usr/bin/env python3
"""Add a stable health alias without modifying the upstream LLMGoat source."""

from __future__ import annotations

from flask import jsonify
from llmgoat.app import app, main


@app.get("/healthz")
def healthz():
    """Report only process readiness; model busy state has its own endpoint."""

    return jsonify({"ok": True, "service": "llmgoat"})


if __name__ == "__main__":
    main()
