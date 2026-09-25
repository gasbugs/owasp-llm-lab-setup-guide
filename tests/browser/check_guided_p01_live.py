"""P01 live Browser button, error/complete state, raw output and responsive UI."""
import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright
from day3_ui_helpers import validate_loopback_origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('output', type=Path)
    parser.add_argument('--source-digest', required=True)
    parser.add_argument('--incomplete', action='store_true')
    args = parser.parse_args()
    origin = validate_loopback_origin(args.url)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, color_scheme='dark')
            page.route('**/*', lambda route: route.continue_()
                       if route.request.url.startswith(origin + '/') else route.abort())
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin, wait_until='networkidle')
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            with page.expect_response(lambda response: response.url.endswith('/api/practice/P01/verify'), timeout=240000) as pending:
                page.locator('#verify').click()
            response = pending.value
            body = response.json()
            args.output.with_suffix('.response.json').write_text(json.dumps(body, ensure_ascii=False, indent=2))
            complete = not args.incomplete
            assert response.status == (200 if complete else 502)
            result = body if complete else body['detail']
            assert result['activity_id'] == 'P01'
            assert result['task_completed'] is complete
            assert result['security_verdict'] == ('PASS' if complete else 'ERR')
            label = 'P01 과제: ' + ('완료' if complete else '미완료')
            page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
            rendered = json.loads(page.locator('#raw').inner_text())
            # Error rendering adds a next-check default but must preserve every
            # server-provided field; successful evidence is byte-value complete.
            assert all(rendered.get(key) == value for key, value in result.items())
            if complete:
                assert rendered == result
                assert result['result']['source_digest'] == args.source_digest
                assert len(result['result']['cases']) == 21
                assert page.locator('#requested-max').inner_text() == '512'
                assert page.locator('#forwarded-max').inner_text() == '128'
            else:
                assert 'Gateway HTTP 501' in result['reason']
                assert page.locator('#forwarded-max').inner_text() == '—'
            rejected = page.evaluate('''async () => {
                const bootstrap = await (await fetch('/api/bootstrap')).json();
                return (await fetch('/api/practice/P01/verify', {method: 'POST',
                    headers: {'X-CSRF-Token': bootstrap.csrf_token, 'Content-Type': 'application/json'},
                    body: JSON.stringify({task_completed: true})})).status;
            }''')
            assert rejected == 422
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                page.locator('#verify').focus()
                page.locator('#verify-help').wait_for(state='visible')
                assert page.evaluate('''() => {
                    const tip = document.querySelector('#verify-help').getBoundingClientRect();
                    const work = document.querySelector('.workbench').getBoundingClientRect();
                    return tip.left >= Math.max(0, work.left) - 1
                        && tip.right <= Math.min(innerWidth, work.right) + 1
                        && document.documentElement.scrollWidth <= innerWidth;
                }'''), f'overflow at {width}px'
                help_button = page.locator('[aria-controls="verify-help"]')
                help_button.click()
                assert help_button.get_attribute('aria-expanded') == 'true'
                help_button.press('Escape')
                assert help_button.get_attribute('aria-expanded') == 'false'
                page.locator('#h01-work').scroll_into_view_if_needed()
                page.screenshot(path=str(args.output.with_suffix(f'.{width}.png')))
            page.locator('[data-theme-choice="light"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'light'
            page.locator('[data-theme-choice="dark"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            assert errors == []
            args.output.write_text(json.dumps({'http_status': response.status, 'response': body,
                'submitted_verdict_status': rejected, 'page_errors': errors, 'viewports': [1440, 390],
                'keyboard_mobile_tooltip': True, 'system_manual_theme': True}, ensure_ascii=False, indent=2))
            print(json.dumps({'task_completed': complete, 'source_digest': args.source_digest}), flush=True)
        finally:
            browser.close()


if __name__ == '__main__':
    main()
