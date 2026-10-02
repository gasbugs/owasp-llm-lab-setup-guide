#!/usr/bin/env python3
"""Reject E2E base URLs that are not strict loopback HTTP origins."""

from __future__ import annotations

import sys
from urllib.parse import urlsplit


PROXY_PATHS = {"/prompt-rag", "/data-rag", "/output-rag", "/knowledge-rag", "/resource-rag", "/llm04-rag", "/vuln-agent", "/llmgoat", "/dvla", "/fake-registry", "/ollama"}

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_strict_loopback_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if port is None and parsed.path.rstrip("/") in PROXY_PATHS:
            port = 80
    except ValueError:
        return False

    return (
        parsed.scheme == "http"
        and parsed.hostname in LOOPBACK_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port is not None
        and 1 <= port <= 65535
        and (parsed.path in ("", "/") or parsed.path.rstrip("/") in PROXY_PATHS)
        and not parsed.query
        and not parsed.fragment
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not is_strict_loopback_url(argv[1]):
        value = argv[1] if len(argv) > 1 else "<missing>"
        print(f"ERROR: E2E target must be a strict loopback HTTP origin: {value}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
