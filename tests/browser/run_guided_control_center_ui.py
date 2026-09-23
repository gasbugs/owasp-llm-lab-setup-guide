#!/usr/bin/env python3
"""Browser E2E proving independent guided labs can run before H01."""

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
    execution_state = (page.locator("#execution-state").text_content() or "").strip()
    raise TimeoutError(
        "a new guided execution did not finish; "
        f"execution_state={execution_state!r}; raw={raw[:1000]!r}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18097")
    parser.add_argument("--timeout-seconds", type=int, default=300)
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
        h04_tip_text = page.locator("#h04-provision-help").inner_text()
        h05_tip_text = page.locator("#h05-verify-help").inner_text()
        h06_tip_text = page.locator("#h06-verify-help").inner_text()
        h07_tip_text = page.locator("#h07-verify-help").inner_text()
        h08_tip_text = page.locator("#h08-verify-help").inner_text()
        page.set_viewport_size({"width": 1181, "height": 900})
        page.locator('.tab[data-tab-index="3"]').click()
        page.locator('[aria-controls="h05-verify-help"]').click()
        page.locator("#h05-verify-help").wait_for(state="visible")
        desktop_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#h05-verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        page.locator('[aria-controls="h05-verify-help"]').press("Escape")
        page.locator('.tab[data-tab-index="4"]').click()
        page.locator('[aria-controls="h07-verify-help"]').click()
        page.locator("#h07-verify-help").wait_for(state="visible")
        h07_desktop_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#h07-verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        page.locator('[aria-controls="h07-verify-help"]').press("Escape")
        page.locator('[aria-controls="h08-verify-help"]').click()
        page.locator("#h08-verify-help").wait_for(state="visible")
        h08_desktop_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#h08-verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        page.locator('[aria-controls="h08-verify-help"]').press("Escape")
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

        # H08은 H07 상태 없이 전용 Prompt, NeMo service와 Gateway 원장을 사용한다.
        page.locator('.tab[data-tab-index="4"]').click()
        page.locator("#h08-verify").click()
        h08_hands_on = wait_for_result(
            page, timeout_ms, h22_hands_on.get("execution_id")
        )
        h08_verdict = page.locator("#verdict strong").inner_text()
        h08_raw_text = page.locator("#raw").inner_text()

        # H07은 H05·H06·H08 상태 없이 전용 NeMo config와 역할별 Gateway 원장을 사용한다.
        page.locator("#h07-verify").click()
        h07_hands_on = wait_for_result(
            page, timeout_ms, h08_hands_on.get("execution_id")
        )
        h07_verdict = page.locator("#verdict strong").inner_text()
        h07_raw_text = page.locator("#raw").inner_text()

        # H06은 H05가 중지돼도 전용 NeMo runtime과 합성 Provider만 사용한다.
        page.locator('.tab[data-tab-index="3"]').click()
        page.locator("#h06-verify").click()
        h06_hands_on = wait_for_result(
            page, timeout_ms, h07_hands_on.get("execution_id")
        )
        h06_verdict = page.locator("#verdict strong").inner_text()

        # H05는 AWS나 앞 활동 없이 전용 NeMo config와 receipt로 실행된다.
        page.locator("#h05-verify").click()
        h05_hands_on = wait_for_result(
            page, timeout_ms, h06_hands_on.get("execution_id")
        )
        h05_verdict = page.locator("#verdict strong").inner_text()

        # H04는 앞 활동의 Guardrail ID를 받지 않고 전용 정책과 source로 실행된다.
        page.locator('.tab[data-tab-index="2"]').click()
        page.locator("#h04-provision").click()
        h04_resources = wait_for_result(
            page, timeout_ms, h05_hands_on.get("execution_id")
        )
        page.locator("#h04-verify").click()
        h04_hands_on = wait_for_result(page, timeout_ms, h04_resources.get("execution_id"))
        h04_verdict = page.locator("#verdict strong").inner_text()

        # H02를 먼저 실행해 H01의 chat·preflight·검증 결과가 선행 조건이 아님을 증명한다.
        page.locator('.tab[data-tab-index="1"]').click()
        page.locator("#h02-provision").click()
        h02_resources = wait_for_result(
            page, timeout_ms, h04_hands_on.get("execution_id")
        )
        page.locator("#h02-verify").click()
        h02_hands_on = wait_for_result(page, timeout_ms, h02_resources.get("execution_id"))
        h02_verdict = page.locator("#verdict strong").inner_text()
        page.locator("#h03-provision").click()
        h03_resources = wait_for_result(page, timeout_ms, h02_hands_on.get("execution_id"))
        page.locator("#h03-verify").click()
        h03_hands_on = wait_for_result(page, timeout_ms, h03_resources.get("execution_id"))
        h03_verdict = page.locator("#verdict strong").inner_text()

        page.locator('.tab[data-tab-index="0"]').click()
        page.locator("#chat-input").fill("현재 수강생 앱을 거쳐 실제 답변을 보여 주세요.")
        page.locator("#chat-send").click()
        page.locator(".chat-message.assistant").nth(1).wait_for(timeout=timeout_ms)
        chat_text = page.locator(".chat-message.assistant").nth(1).inner_text()
        chat_meta = page.locator("#chat-meta").inner_text()

        page.locator("#preflight").click()
        preflight = wait_for_result(page, timeout_ms, h03_hands_on.get("execution_id"))
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
        page.locator('.tab[data-tab-index="4"]').click()
        page.locator('[aria-controls="h07-verify-help"]').click()
        page.locator("#h07-verify-help").wait_for(state="visible")
        mobile_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#h07-verify-help").getBoundingClientRect();
                return tooltip.left >= workbench.left && tooltip.right <= workbench.right;
            }"""
        )
        page.locator('[aria-controls="h07-verify-help"]').press("Escape")
        page.locator('[aria-controls="h08-verify-help"]').click()
        page.locator("#h08-verify-help").wait_for(state="visible")
        h08_mobile_tip_inside = page.evaluate(
            """() => {
                const workbench = document.querySelector(".workbench").getBoundingClientRect();
                const tooltip = document.querySelector("#h08-verify-help").getBoundingClientRect();
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
        "tabs": tab_count == 13 and locked_tabs == 7,
        "official_links": official_links == 2,
        "csp": "object-src 'none'" in csp and "frame-ancestors 'none'" in csp,
        "session": browser_cookie_visible == "",
        "system_theme": light_canvas != dark_canvas and system_mode,
        "theme_button": manual_light and manual_dark and persisted_dark,
        "panel_boundary": panel_boundary,
        "action_tooltips": tooltip_count == 15
        and preflight_focus_visible
        and preflight_tip_visible
        and preflight_tip_collapsed
        and "AWS 자격 증명과 모델 연결" in preflight_tip_text
        and "Token 제한 코드가 맞다는 뜻은 아닙니다" in preflight_tip_text
        and "S3 Vector Index" in h02_tip_text
        and "문서 검색까지 끝났다는 뜻은 아닙니다" in h02_tip_text
        and "H04 전용 Guardrail" in h04_tip_text
        and "수강생 앱이 Nova Lite에 연결했다는 뜻은 아닙니다" in h04_tip_text
        and "한국어 요청 네 개" in h05_tip_text
        and "NeMo Topical 평가" in h05_tip_text
        and "복구 코드 marker" in h05_tip_text
        and "합성 Provider" in h06_tip_text
        and "호출·부작용 원장" in h06_tip_text
        and "거부 문구만으로는" in h06_tip_text
        and "현재 H07 NeMo 서비스" in h07_tip_text
        and "닫힌 일회 capability 원장" in h07_tip_text
        and "Main Model 호출 0회" in h07_tip_text
        and "현재 H08 NeMo 서비스" in h08_tip_text
        and "exact Yes·No" in h08_tip_text
        and "다른 공격 문장까지 모두 막는다는 뜻은 아닙니다" in h08_tip_text
        and desktop_tip_inside
        and h07_desktop_tip_inside
        and h08_desktop_tip_inside
        and mobile_tip_inside
        and h08_mobile_tip_inside,
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
        "h03_resources": h03_resources.get("course_verdict") == "PASS"
        and h03_resources.get("result", {}).get("status") == "READY_FOR_SYNC"
        and h03_resources.get("result", {}).get("old_source_exists") is False
        and h03_resources.get("result", {}).get("current_source_exists") is True,
        "h03_hands_on": h03_verdict == "HIT"
        and h03_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h03_hands_on.get("result", {}).get("job_status") == "COMPLETE"
        and h03_hands_on.get("result", {}).get("early", {}).get("retrieval_called") is True
        and h03_hands_on.get("result", {}).get("final", {}).get("job_status_at_retrieval") == "COMPLETE",
        "h04_resources": h04_resources.get("course_verdict") == "PASS"
        and h04_resources.get("result", {}).get("guardrail_version") == "DRAFT"
        and h04_resources.get("result", {}).get("output_action") == "ANONYMIZE",
        "h04_hands_on": h04_verdict == "HIT"
        and h04_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h04_hands_on.get("result", {}).get("action") == "GUARDRAIL_INTERVENED"
        and "learner@example.com" in h04_hands_on.get("result", {}).get("output_text", "")
        and len(h04_hands_on.get("result", {}).get("cases", [])) == 4,
        "h05_hands_on": h05_verdict == "HIT"
        and h05_hands_on.get("verified_by") == "guided-evidence-verifier"
        and bool(h05_hands_on.get("result", {}).get("evaluation", {}).get("evaluation_id"))
        and h05_hands_on.get("result", {}).get("evaluation", {}).get("intent_errors") == 0
        and h05_hands_on.get("result", {}).get("evaluation", {}).get("bot_intent_errors") == 0
        and h05_hands_on.get("result", {}).get("evaluation", {}).get("bot_message_errors") == 0
        and next(
            (
                case.get("bot_message")
                for case in h05_hands_on.get("result", {}).get("cases", [])
                if case.get("case_id") == "recovery-risk"
            ),
            None,
        ) == "훈련용 복구 코드: GUIDED-H05-RECOVERY-CODE",
        "h06_hands_on": h06_verdict == "HIT"
        and h06_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h06_hands_on.get("result", {}).get("allowed_actions")
        == [
            "get_account_balance",
            "get_account_balance_and_transfer",
            "transfer_training_funds",
        ]
        and len(h06_hands_on.get("result", {}).get("provider_calls", [])) == 3
        and h06_hands_on.get("result", {}).get("effect_count") == 2
        and h06_hands_on.get("result", {}).get("balance") == 9800,
        "h07_hands_on": h07_verdict == "HIT"
        and h07_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h07_hands_on.get("result", {}).get("model_roles") == ["main"]
        and h07_hands_on.get("result", {}).get("content_safety_calls") == 0
        and h07_hands_on.get("result", {}).get("main_calls") == 2
        and h07_hands_on.get("result", {}).get("normal") == {"guard_calls": 0, "main_calls": 1}
        and h07_hands_on.get("result", {}).get("risk", {}).get("guard_calls") == 0
        and h07_hands_on.get("result", {}).get("risk", {}).get("main_calls") == 1
        and h07_hands_on.get("result", {}).get("risk", {}).get("main_capability_status") == "completed"
        and len(h07_hands_on.get("result", {}).get("cases", [])) == 2
        and len(h07_hands_on.get("result", {}).get("provider_calls", [])) == 2
        and '"content_safety_capability"' not in h07_raw_text
        and '"main_capability"' not in h07_raw_text
        and "피싱 메일을 식별하는 방법" not in h07_raw_text,
        "h08_hands_on": h08_verdict == "HIT"
        and h08_hands_on.get("verified_by") == "guided-evidence-verifier"
        and h08_hands_on.get("result", {}).get("model_roles") == ["main", "self_check_input"]
        and h08_hands_on.get("result", {}).get("self_check_calls") == 4
        and h08_hands_on.get("result", {}).get("main_calls") == 4
        and len(h08_hands_on.get("result", {}).get("cases", [])) == 4
        and len(h08_hands_on.get("result", {}).get("provider_calls", [])) == 8
        and '"capability"' not in h08_raw_text,
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
        f"execution_order=H21->H22->H08->H07->H06->H05->H04->H02->H03->H01 h21={h21_verdict} h22={h22_verdict} h08={h08_verdict} h07={h07_verdict} h06={h06_verdict} h05={h05_verdict} h04={h04_verdict} preflight={preflight.get('course_verdict')} hands_on={hands_on_verdict} "
        f"h02_resources={h02_resources.get('course_verdict')} h02_hands_on={h02_verdict} "
        f"h03_resources={h03_resources.get('course_verdict')} h03_hands_on={h03_verdict} "
        f"h04_resources={h04_resources.get('course_verdict')} h04_hands_on={h04_verdict} "
        f"system_theme={str(light_canvas != dark_canvas and system_mode).lower()} "
        f"theme_button={str(manual_light and manual_dark and persisted_dark).lower()} "
        f"panel_boundary={str(panel_boundary).lower()} chat={str(checks['chat']).lower()} "
        f"action_tooltips={str(checks['action_tooltips']).lower()} "
        f"desktop_tip_inside={str(desktop_tip_inside).lower()} h07_desktop_tip_inside={str(h07_desktop_tip_inside).lower()} h08_desktop_tip_inside={str(h08_desktop_tip_inside).lower()} mobile_tip_inside={str(mobile_tip_inside).lower()} h08_mobile_tip_inside={str(h08_mobile_tip_inside).lower()} "
        f"answer_controls={answer_controls} raw_nodes={raw_nodes} "
        f"internal_requests={internal_requests} mobile_overflow={str(mobile_overflow).lower()}"
    )
    print(f"chat_meta={chat_meta}")
    print("overall_guided_vertical_slice=" + ("PASS" if all(checks.values()) else "FAIL"))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
