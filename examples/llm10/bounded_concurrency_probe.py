#!/usr/bin/env python3
"""Run a bounded LLM10 concurrency probe and print every HTTP status."""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def request_once(url: str, timeout: float) -> int:
    body = json.dumps(
        {"message": "rate limit probe", "user_id": "llm10-bounded"}
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code
    except (urllib.error.URLError, TimeoutError):
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8013/api/chat")
    parser.add_argument("--requests", type=int, default=10)
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    if not 1 <= args.requests <= 20 or not 1 <= args.parallel <= 4:
        parser.error("requests must be 1..20 and parallel must be 1..4")

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        statuses = list(
            executor.map(
                lambda _: request_once(args.url, args.timeout),
                range(args.requests),
            )
        )
    result = {
        "requests": args.requests,
        "parallel": args.parallel,
        "statuses": statuses,
        "http_200": statuses.count(200),
        "http_429": statuses.count(429),
        "transport_errors": statuses.count(0),
        "classification": (
            "verified_no_rate_limit"
            if statuses.count(200) == args.requests
            else "rate_limit_enforced"
            if statuses.count(429) > 0 and statuses.count(0) == 0
            else "transport_or_unexpected_status"
        ),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
