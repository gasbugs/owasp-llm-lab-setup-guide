"""P02 actual Browser request, raw result, completion, help and responsive theme."""
import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright
from day3_ui_helpers import validate_loopback_origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--incomplete", action="store_true")
    args = parser.parse_args()
    origin = validate_loopback_origin(args.url)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, color_scheme="dark")
            page.route("**/*", lambda route: route.continue_()
                       if route.request.url.startswith(origin + "/") else route.abort())
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin, wait_until="networkidle")
            page.locator('.tab[data-tab-index="1"]').click()
            assert page.locator("html").get_attribute("data-theme") == "dark"
            assert "learner.py" in page.locator("#h02-work").inner_text()
            with page.expect_response(lambda response: response.url.endswith("/api/practice/P02/verify"), timeout=240000) as pending:
                page.locator("#h02-verify").click()
            response = pending.value
            result = response.json()
            args.output.with_suffix(".response.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
            complete = not args.incomplete
            assert response.status == 200 and result["activity_id"] == "P02"
            assert result["task_completed"] is complete
            assert result["security_verdict"] == ("PASS" if complete else "ERR")
            label = "P02 과제: " + ("완료" if complete else "미완료")
            page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
            assert json.loads(page.locator("#raw").inner_text()) == result
            assert page.locator("#provider-id").inner_text() == result["execution_id"]
            assert page.locator("#requested-max").inner_text() == ("22" if complete else "—")
            assert page.locator("#forwarded-max").inner_text() == ("1024" if complete else "—")
            if complete:
                assert result["result"]["source_digest"] == args.source_digest
            rejected = page.evaluate('''async () => {
                const bootstrap = await (await fetch('/api/bootstrap')).json();
                return (await fetch('/api/practice/P02/verify', {method: 'POST',
                    headers: {'X-CSRF-Token': bootstrap.csrf_token, 'Content-Type': 'application/json'},
                    body: JSON.stringify({task_completed: true})})).status;
            }''')
            assert rejected == 422
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                for action in ("h02-provision", "h02-verify"):
                    page.locator("#" + action).focus()
                    page.locator("#" + action + "-help").wait_for(state="visible")
                    assert page.evaluate('''(id) => {
                        const tip = document.getElementById(id).getBoundingClientRect();
                        const work = document.querySelector('.workbench').getBoundingClientRect();
                        return tip.left >= Math.max(0, work.left) - 1
                            && tip.right <= Math.min(innerWidth, work.right) + 1
                            && document.documentElement.scrollWidth <= innerWidth;
                    }''', action + "-help")
                    help_button = page.locator('[aria-controls="' + action + '-help"]')
                    help_button.click()
                    assert help_button.get_attribute("aria-expanded") == "true"
                    help_button.press("Escape")
                    assert help_button.get_attribute("aria-expanded") == "false"
                page.locator("#h02-work").scroll_into_view_if_needed()
                page.screenshot(path=str(args.output.with_suffix(f".{width}.png")))
            for theme in ("light", "dark"):
                page.locator(f'[data-theme-choice="{theme}"]').click()
                assert page.locator("html").get_attribute("data-theme") == theme
            assert errors == []
            args.output.write_text(json.dumps({"http_status": response.status, "response": result,
                "submitted_verdict_status": rejected, "page_errors": errors, "viewports": [1440, 390],
                "keyboard_mobile_tooltip": True, "system_manual_theme": True}, ensure_ascii=False, indent=2))
        finally:
            browser.close()


if __name__ == "__main__":
    main()
