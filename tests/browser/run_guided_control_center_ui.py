#!/usr/bin/env python3
"""03 테넌트 UI의 실제 Application 경로와 390px 화면을 검사한다."""

from __future__ import annotations

import argparse
import json
from urllib.parse import urlsplit

from day3_ui_helpers import browser_url_is_local, validate_loopback_origin


def run_lesson(page, number: int, timeout_ms: int) -> dict:
    page.locator(".lesson-button").nth(number - 1).click()
    page.locator("#raw").evaluate("element => { element.textContent = ''; }")
    page.locator("#run").click()
    page.wait_for_function(
        "() => document.querySelector('#raw').textContent.trim().startsWith('{')",
        timeout=timeout_ms,
    )
    return json.loads(page.locator("#raw").text_content() or "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18097")
    parser.add_argument("--timeout-seconds", type=int, default=360)
    parser.add_argument("--browser-channel", default="chromium")
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
        page.goto(origin, wait_until="domcontentloaded", timeout=timeout_ms)
        lesson_count = page.locator(".lesson-button").count()
        page.wait_for_function(
            "() => document.querySelectorAll('.official-card .official-status.ready').length >= 3",
            timeout=timeout_ms,
        )
        official_cards = page.locator(".official-card").count()
        official_ready = page.locator(".official-card .official-status.ready").count()
        official_external = page.locator(".official-card .official-status.external").count()

        normal = run_lesson(page, 1, timeout_ms)
        normal_verdict = page.locator("#verdict strong").inner_text()
        model_gate = page.locator('[data-gate="model"]').get_attribute("class") or ""

        attack = run_lesson(page, 2, timeout_ms)
        attack_verdict = page.locator("#verdict strong").inner_text()
        attack_model_gate = page.locator('[data-gate="model"]').get_attribute("class") or ""

        page.set_viewport_size({"width": 390, "height": 844})
        mobile_overflow = page.evaluate(
            "() => document.documentElement.scrollWidth > document.documentElement.clientWidth"
        )
        browser.close()

    same_origin_requests = sum(url == f"{origin}/api/chat" for url in requests)
    internal_requests = sum(
        urlsplit(url).port in {18093, 18094, 18095, 18096}
        for url in requests
        if urlsplit(url).hostname in {"127.0.0.1", "localhost"}
    )
    checks = {
        "lessons": lesson_count == 22,
        "official_uis": official_cards == 6
        and official_ready >= 3
        and official_external == 2,
        "normal": normal.get("application_decision") == "allow"
        and normal.get("upstream_called") is True
        and normal_verdict == "PASS"
        and "pass" in model_gate,
        "attack": attack.get("application_decision") == "block"
        and attack.get("upstream_called") is False
        and attack_verdict == "PASS"
        and "skip" in attack_model_gate,
        "same_origin": same_origin_requests == 2 and internal_requests == 0,
        "mobile": mobile_overflow is False,
    }
    print(
        f"lessons={lesson_count} official_cards={official_cards} "
        f"official_ready={official_ready} official_external={official_external} "
        f"normal={normal_verdict} attack={attack_verdict} "
        f"same_origin_chat={same_origin_requests} internal_requests={internal_requests} "
        f"mobile_overflow={str(mobile_overflow).lower()}"
    )
    print("overall_guided_ui=" + ("PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
