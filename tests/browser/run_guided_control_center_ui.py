#!/usr/bin/env python3
"""Browser E2E for the tenant 03 activity 01 vertical slice."""

from __future__ import annotations

import argparse
import json
import time
from urllib.parse import urlsplit

from day3_ui_helpers import browser_url_is_local, validate_loopback_origin


def wait_for_result(page, timeout_ms: int, previous_id: str | None = None) -> dict:
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        raw = (page.locator("#raw").text_content() or "").strip()
        if raw.startswith("{"):
            payload = json.loads(raw)
            if payload.get("execution_id") != previous_id:
                return payload
        page.wait_for_timeout(100)
    raise TimeoutError("a new guided execution did not finish")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18097")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--browser-channel", default="chromium")
    parser.add_argument("--screenshot", default="")
    args = parser.parse_args()
    origin = validate_loopback_origin(args.url)
    timeout_ms = args.timeout_seconds * 1000

    from playwright.sync_api import sync_playwright

    requests: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=args.browser_channel, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1100})
        context.route(
            "**/*",
            lambda route, request: route.continue_()
            if browser_url_is_local(request.url)
            else route.abort("blockedbyclient"),
        )
        page = context.new_page()
        page.on("request", lambda request: requests.append(request.url))
        response = page.goto(origin, wait_until="networkidle", timeout=timeout_ms)
        assert response is not None

        tab_count = page.locator(".tab").count()
        locked_tabs = page.locator(".tab.locked").count()
        official_links = page.locator(".official-link").count()
        csp = response.headers.get("content-security-policy", "")
        browser_cookie_visible = page.evaluate("() => document.cookie")

        page.locator("#preflight").click()
        preflight = wait_for_result(page, timeout_ms)

        answer_controls = page.locator("select, input[type=checkbox], #hint, #reset").count()
        page.locator("#verify").click()
        hands_on = wait_for_result(page, timeout_ms, preflight.get("execution_id"))
        hands_on_verdict = page.locator("#verdict strong").inner_text()
        raw_nodes = page.locator("#raw img, #raw script").count()

        if args.screenshot:
            page.screenshot(path=args.screenshot, full_page=True)

        page.set_viewport_size({"width": 390, "height": 844})
        mobile_overflow = page.evaluate(
            "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
        )
        browser.close()

    internal_requests = sum(
        urlsplit(url).hostname
        in {
            "guided-control-center",
            "guided-student-app",
            "guided-evidence-verifier",
            "guided-bedrock-gateway",
        }
        for url in requests
    )
    checks = {
        "tabs": tab_count == 13 and locked_tabs == 12,
        "official_links": official_links == 2,
        "csp": "object-src 'none'" in csp and "frame-ancestors 'none'" in csp,
        "session": browser_cookie_visible == "",
        "preflight": preflight.get("course_verdict") == "PASS"
        and preflight.get("result", {}).get("forwarded_parameters", {}).get("maxTokens") == 2,
        "hands_on": hands_on_verdict == "HIT"
        and hands_on.get("verified_by") == "guided-evidence-verifier"
        and hands_on.get("result", {}).get("forwarded_parameters", {}).get("maxTokens") == 512
        and len(hands_on.get("result", {}).get("cases", [])) == 2,
        "learner_work": answer_controls == 0,
        "safe_rendering": raw_nodes == 0,
        "same_origin": internal_requests == 0,
        "mobile": mobile_overflow is False,
    }
    print(
        f"tabs={tab_count} locked_tabs={locked_tabs} official_links={official_links} "
        f"preflight={preflight.get('course_verdict')} hands_on={hands_on_verdict} "
        f"answer_controls={answer_controls} raw_nodes={raw_nodes} "
        f"internal_requests={internal_requests} mobile_overflow={str(mobile_overflow).lower()}"
    )
    print("overall_guided_vertical_slice=" + ("PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
