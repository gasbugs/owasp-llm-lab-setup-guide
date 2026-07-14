#!/usr/bin/env python3
"""Instructor-only LLMGoat A01 browser/API evidence over one SSM forward."""
from __future__ import annotations

import argparse
import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from day3_ui_helpers import (
    format_llmgoat_course_output,
    sha256_file,
    validate_loopback_origin,
)
from run_day3_ui import (
    build_hash_manifest,
    fetch_text,
    llmgoat_request_count,
    now_iso,
    run_llmgoat,
    write_json,
)


SCHEMA_VERSION = 1
DEFAULT_LLMGOAT_URL = "http://127.0.0.1:15000"


def preflight_llmgoat(llmgoat_url: str) -> dict[str, Any]:
    """Require a healthy, idle LLMGoat model before spending a browser request."""
    status, body = fetch_text(llmgoat_url + "/api/model_status")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("LLMGoat /api/model_status did not return JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("LLMGoat /api/model_status did not return an object")
    if (
        status != 200
        or not isinstance(payload.get("model_busy"), bool)
        or payload["model_busy"]
    ):
        raise RuntimeError("LLMGoat model is missing or busy before UI validation")
    return {"status": status, "body": payload}


def observed_a01_request_count(
    records: list[dict[str, Any]], llmgoat_url: str | None
) -> int:
    """Count captured A01 POSTs, including requests followed by a DOM failure."""
    if llmgoat_url is None:
        return 0
    return llmgoat_request_count(records, llmgoat_url)


def failure_evidence(reason: str, *, request_count: int) -> dict[str, Any]:
    """Return a printable, fail-closed result even when the browser cannot run."""
    return {
        "status": "FAIL",
        "failure_class": "F-HARNESS",
        "reason": reason,
        "request_count": request_count,
        "overlay_visible": None,
        "sidebar_completed": None,
        "checks": {
            "one_api_request": False,
            "exact_response_rendered": False,
            "overlay_matches_solved": False,
            "sidebar_matches_solved": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--llmgoat-url",
        default=os.environ.get("LLMGOAT_URL", DEFAULT_LLMGOAT_URL),
    )
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument(
        "--browser-channel",
        choices=("chromium", "chrome", "msedge"),
        default=os.environ.get("PLAYWRIGHT_BROWSER_CHANNEL", "chromium"),
        help="use bundled Chromium, or an installed Chrome/Edge channel",
    )
    parser.add_argument("--headed", action="store_true")
    parser.add_argument(
        "--result-dir",
        type=Path,
        default=Path(__file__).parent
        / "results"
        / ("llmgoat-a01-" + datetime.now().strftime("%Y%m%d-%H%M%S")),
    )
    args = parser.parse_args(argv)
    if not 20 <= args.timeout_seconds <= 300:
        parser.error("--timeout-seconds must be between 20 and 300")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result_dir = args.result_dir.expanduser().resolve()
    result_dir.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": now_iso(),
        "status": "FAIL",
        "target": None,
        "preflight": None,
        "llmgoat": {"status": "NOT_RUN"},
        "cleanup": {"browser_closed": False},
    }
    records: list[dict[str, Any]] = []
    browser: Any = None
    llmgoat_url: str | None = None
    evidence = failure_evidence(
        "LLMGoat validation did not run", request_count=0
    )
    try:
        llmgoat_url = validate_loopback_origin(args.llmgoat_url)
        result["target"] = llmgoat_url
        result["preflight"] = preflight_llmgoat(llmgoat_url)
        try:
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Playwright is missing; install tests/browser/requirements.txt and Chromium"
            ) from exc

        with sync_playwright() as playwright:
            launch_options: dict[str, Any] = {"headless": not args.headed}
            if args.browser_channel != "chromium":
                launch_options["channel"] = args.browser_channel
            browser = playwright.chromium.launch(**launch_options)
            try:
                evidence = run_llmgoat(
                    browser,
                    llmgoat_url,
                    result_dir,
                    records,
                    args.timeout_seconds * 1000,
                )
            finally:
                browser.close()
                browser = None
                result["cleanup"]["browser_closed"] = True
        result["llmgoat"] = evidence
        result["status"] = evidence.get("status", "FAIL")
    except Exception as exc:
        evidence = failure_evidence(
            str(exc),
            request_count=observed_a01_request_count(records, llmgoat_url),
        )
        result["llmgoat"] = evidence
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        (result_dir / "traceback.txt").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
    finally:
        if browser is not None:
            try:
                browser.close()
                result["cleanup"]["browser_closed"] = True
            except Exception as exc:
                result["cleanup"]["browser_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
        if result["status"] == "PASS" and not result["cleanup"]["browser_closed"]:
            result["status"] = "FAIL"
            evidence = failure_evidence(
                "browser cleanup was not proven",
                request_count=observed_a01_request_count(records, llmgoat_url),
            )
            result["llmgoat"] = evidence
        result["cleanup"]["status"] = (
            "PASS" if result["cleanup"]["browser_closed"] else "FAIL"
        )
        write_json(result_dir / "network-events.json", records)
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest = build_hash_manifest(result_dir)
        write_json(result_dir / "sha256sums.json", manifest)
        result["evidence_file_count"] = len(manifest)
        result["sha256_manifest_sha256"] = sha256_file(
            result_dir / "sha256sums.json"
        )
        write_json(result_dir / "result.json", result)

    for line in format_llmgoat_course_output(evidence):
        print(line)
    print(f"RESULT_DIR={result_dir}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
