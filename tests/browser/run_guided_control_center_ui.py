#!/usr/bin/env python3
"""Browser E2E proving H02 can run before H01 in the tenant 03 platform."""

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
        light_canvas = page.evaluate("() => getComputedStyle(document.body).backgroundColor")
        page.emulate_media(color_scheme="dark")
        page.locator("html[data-theme=dark]").wait_for()
        dark_canvas = page.evaluate("() => getComputedStyle(document.body).backgroundColor")
        system_mode = page.evaluate("() => document.documentElement.dataset.themeMode === 'system'")
        page.locator('[data-theme-choice="light"]').click()
        manual_light = page.evaluate(
            "() => document.documentElement.dataset.themeMode === 'light' && document.documentElement.dataset.theme === 'light'"
        )
        page.locator('[data-theme-choice="dark"]').click()
        manual_dark = page.evaluate(
            "() => document.documentElement.dataset.themeMode === 'dark' && document.documentElement.dataset.theme === 'dark'"
        )
        page.reload(wait_until="networkidle", timeout=timeout_ms)
        persisted_dark = page.evaluate(
            "() => document.documentElement.dataset.themeMode === 'dark' && document.documentElement.dataset.theme === 'dark'"
        )
        panel_boundary = page.evaluate(
            "() => { const nav = document.querySelector('.route-panel').getBoundingClientRect(); const work = document.querySelector('.workbench').getBoundingClientRect(); return work.left - nav.right >= 16; }"
        )
        tooltip_count = page.locator('[role="tooltip"].action-tooltip').count()
        page.locator("#preflight").focus()
        page.locator("#preflight-help").wait_for(state="visible")
        preflight_focus_visible = page.locator("#preflight-help").is_visible()
        page.locator('[aria-controls="preflight-help"]').click()
        preflight_tip = page.locator("#preflight-help")
        preflight_tip.wait_for(state="visible")
        preflight_tip_visible = preflight_tip.is_visible()
        preflight_tip_text = preflight_tip.inner_text()
        page.locator('[aria-controls="preflight-help"]').press("Escape")
        preflight_tip_collapsed = page.locator('[aria-controls="preflight-help"]').get_attribute("aria-expanded") == "false"
        h02_tip_text = page.locator("#h02-provision-help").inner_text()
        page.set_viewport_size({"width": 1181, "height": 900})
        page.locator('[aria-controls="verify-help"]').click()
        page.locator("#verify-help").wait_for(state="visible")
        desktop_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        page.locator('[aria-controls="verify-help"]').press("Escape")
        page.set_viewport_size({"width": 1440, "height": 1100})

        answer_controls = page.locator("select, input[type=checkbox], #hint, #reset").count()
        # H21과 H22도 앞 문제와 무관한 전용 source·container·상태로 실행된다.
        page.locator('.tab[data-tab-index="12"]').click()
        page.locator("#h21-verify").click()
        h21_hands_on = wait_for_result(page, timeout_ms)
        h21_verdict = page.locator("#verdict strong").inner_text()
        page.locator("#h22-verify").click()
        h22_hands_on = wait_for_result(page, timeout_ms, h21_hands_on.get("execution_id"))
        h22_verdict = page.locator("#verdict strong").inner_text()

        # H02를 먼저 실행해 H01의 chat·preflight·검증 결과가 선행 조건이 아님을 증명한다.
        page.locator('.tab[data-tab-index="1"]').click()
        page.locator("#h02-provision").click()
        h02_resources = wait_for_result(
            page, timeout_ms, h22_hands_on.get("execution_id")
        )
        page.locator("#h02-verify").click()
        h02_hands_on = wait_for_result(page, timeout_ms, h02_resources.get("execution_id"))
        h02_verdict = page.locator("#verdict strong").inner_text()

        page.locator('.tab[data-tab-index="0"]').click()
        page.locator("#chat-input").fill("현재 수강생 앱을 거쳐 실제 답변을 보여 주세요.")
        page.locator("#chat-send").click()
        page.locator(".chat-message.assistant").nth(1).wait_for(timeout=timeout_ms)
        chat_text = page.locator(".chat-message.assistant").nth(1).inner_text()
        chat_meta = page.locator("#chat-meta").inner_text()

        page.locator("#preflight").click()
        preflight = wait_for_result(page, timeout_ms, h02_hands_on.get("execution_id"))
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
        page.locator('[aria-controls="verify-help"]').click()
        page.locator("#verify-help").wait_for(state="visible")
        mobile_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        browser.close()

    internal_requests = sum(
        urlsplit(url).hostname
        in {
            "guided-control-center",
            "guided-h01-gateway",
            "guided-evidence-verifier",
            "guided-bedrock-gateway",
        }
        for url in requests
    )
    checks = {
        "tabs": tab_count == 13 and locked_tabs == 10,
        "official_links": official_links == 2,
        "csp": "object-src 'none'" in csp and "frame-ancestors 'none'" in csp,
        "session": browser_cookie_visible == "",
        "system_theme": light_canvas != dark_canvas and system_mode,
        "theme_button": manual_light and manual_dark and persisted_dark,
        "panel_boundary": panel_boundary,
        "action_tooltips": tooltip_count == 7
        and preflight_focus_visible
        and preflight_tip_visible
        and preflight_tip_collapsed
        and "AWS 자격 증명과 모델 연결" in preflight_tip_text
        and "Token 제한 코드가 맞다는 뜻은 아닙니다" in preflight_tip_text
        and "S3 Vector Index" in h02_tip_text
        and "문서 검색까지 끝났다는 뜻은 아닙니다" in h02_tip_text
        and desktop_tip_inside
        and mobile_tip_inside,
        "chat": bool(chat_text.strip())
        and chat_text != "모델 응답을 받지 못했습니다."
        and "requested 512" in chat_meta
        and "effective 512" in chat_meta
        and "provider " in chat_meta,
        "preflight": preflight.get("course_verdict") == "PASS"
        and preflight.get("result", {}).get("forwarded_parameters", {}).get("maxTokens") == 2,
        "hands_on": hands_on_verdict == "HIT"
        and hands_on.get("verified_by") == "guided-evidence-verifier"
        and hands_on.get("result", {}).get("forwarded_parameters", {}).get("maxTokens") == 512
        and len(hands_on.get("result", {}).get("cases", [])) == 4
        and hands_on.get("result", {}).get("cases", [])[2].get("upstream_called") is False
        and hands_on.get("result", {}).get("cases", [])[3].get("upstream_called") is False,
        "h02_resources": h02_resources.get("course_verdict") == "PASS"
        and h02_resources.get("result", {}).get("dimensions") == 1024
        and bool(h02_resources.get("result", {}).get("knowledge_base_id")),
        "h02_hands_on": h02_verdict == "HIT"
        and h02_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h02_hands_on.get("result", {}).get("embedding_dimension") == 1024
        and len(h02_hands_on.get("result", {}).get("cases", [])) == 3
        and h02_hands_on.get("result", {}).get("cases", [])[1].get("object_key", "").startswith("h02/untrusted/")
        and h02_hands_on.get("result", {}).get("cases", [])[2].get("upstream_called") is False,
        "h22_hands_on": h22_verdict == "HIT"
        and h22_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h22_hands_on.get("result", {}).get("protocol_version") == "2026-07-28"
        and h22_hands_on.get("result", {}).get("effect_counts") == [1, 2, 3, 4, 5]
        and h22_hands_on.get("result", {}).get("verified_effects", {}).get("effects") == 5
        and h22_hands_on.get("result", {}).get("external_action_called") is False,
        "h21_hands_on": h21_verdict == "HIT"
        and h21_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h21_hands_on.get("result", {}).get("protocol_version") == "2026-07-28"
        and h21_hands_on.get("result", {}).get("impacts", {}).get("forbidden_model_provider") is True
        and h21_hands_on.get("result", {}).get("impacts", {}).get("untrusted_server_contact") is True
        and h21_hands_on.get("result", {}).get("external_action_called") is False,
        "learner_work": answer_controls == 0,
        "safe_rendering": raw_nodes == 0,
        "same_origin": internal_requests == 0,
        "mobile": mobile_overflow is False,
    }
    print(
        f"tabs={tab_count} locked_tabs={locked_tabs} official_links={official_links} "
        f"execution_order=H21->H22->H02->H01 h21={h21_verdict} h22={h22_verdict} preflight={preflight.get('course_verdict')} hands_on={hands_on_verdict} "
        f"h02_resources={h02_resources.get('course_verdict')} h02_hands_on={h02_verdict} "
        f"system_theme={str(light_canvas != dark_canvas and system_mode).lower()} "
        f"theme_button={str(manual_light and manual_dark and persisted_dark).lower()} "
        f"panel_boundary={str(panel_boundary).lower()} chat={str(checks['chat']).lower()} "
        f"action_tooltips={str(checks['action_tooltips']).lower()} "
        f"desktop_tip_inside={str(desktop_tip_inside).lower()} mobile_tip_inside={str(mobile_tip_inside).lower()} "
        f"answer_controls={answer_controls} raw_nodes={raw_nodes} "
        f"internal_requests={internal_requests} mobile_overflow={str(mobile_overflow).lower()}"
    )
    print(f"chat_meta={chat_meta}")
    print("overall_guided_vertical_slice=" + ("PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
