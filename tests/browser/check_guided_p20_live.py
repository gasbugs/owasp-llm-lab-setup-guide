"""P20 through the actual UI/proxy/services; no response fixtures."""
import argparse
import json
from pathlib import Path
import time
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler

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
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 60
    while True:
        try:
            with opener.open(origin + '/readyz', timeout=3) as response:
                if response.status == 200: break
        except (URLError, TimeoutError):
            pass
        if time.monotonic() >= deadline: raise TimeoutError('Control Center readiness')
        time.sleep(.5)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, color_scheme='dark')
            page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin + '/') else route.abort())
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin, wait_until='networkidle')
            page.locator('.tab[data-tab-index="11"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            with page.expect_response(lambda response: response.url.endswith('/api/practice/P20/verify'), timeout=180000) as pending:
                page.locator('#h20-verify').click()
            response = pending.value
            assert response.status == 200
            result = response.json()
            args.output.with_suffix('.response.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
            expected = not args.incomplete
            assert result['activity_id'] == 'P20'
            assert result['task_completed'] is expected
            assert result['security_verdict'] == ('PASS' if expected else 'ERR')
            assert result['result']['source_digest'] == args.source_digest
            label = 'P20 과제: ' + ('완료' if expected else '미완료')
            page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
            assert json.loads(page.locator('#raw').inner_text()) == result
            assert page.locator('#provider-label').inner_text() == '실행 상태'
            assert page.locator('#provider-id').inner_text() == ('완료' if expected else '오류')
            assert page.locator('#requested-max').inner_text() == ('7' if expected else '6')
            assert page.locator('#forwarded-max').inner_text() == ('종료' if expected else '미종료')
            boundary = page.evaluate('''async () => {
                const bootstrap = await (await fetch('/api/bootstrap')).json();
                return (await fetch('/api/practice/P20/verify', {method: 'POST',
                    headers: {'X-CSRF-Token': bootstrap.csrf_token, 'Content-Type': 'application/json'},
                    body: JSON.stringify({task_completed: true})})).status;
            }''')
            assert boundary == 422
            sizes = []
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                page.locator('#h20-verify').focus()
                page.locator('#h20-help').wait_for(state='visible')
                assert page.evaluate('''() => {
                    const tip = document.querySelector('#h20-help').getBoundingClientRect();
                    const work = document.querySelector('.workbench').getBoundingClientRect();
                    return tip.left >= Math.max(0, work.left) - 1
                        && tip.right <= Math.min(innerWidth, work.right) + 1
                        && document.documentElement.scrollWidth <= innerWidth;
                }'''), f'tooltip or page overflows at {width}px'
                help_button = page.locator('[aria-describedby="h20-help"]')
                help_button.focus()
                assert help_button.evaluate("(button) => button.closest('.action-control').classList.contains('tip-dismissed')") is False
                help_button.press('Escape')
                assert help_button.evaluate("(button) => button.closest('.action-control').classList.contains('tip-dismissed')") is True
                page.locator('#h20-work').scroll_into_view_if_needed()
                page.screenshot(path=str(args.output.with_suffix(f'.{width}.png')))
                sizes.append(width)
            page.locator('[data-theme-choice="light"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'light'
            page.locator('[data-theme-choice="dark"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            assert not errors
            page.screenshot(path=str(args.output.with_suffix('.png')))
            args.output.write_text(json.dumps({'scope': 'Browser→proxy→Control Center→P20→native products→TCP verifier; no AWS',
                'response': result, 'submitted_verdict_status': boundary, 'page_errors': errors,
                'viewports': sizes, 'keyboard_mobile_tooltip': True, 'system_manual_theme': True}, ensure_ascii=False, indent=2))
            print(json.dumps({'task_completed': expected, 'source_digest': args.source_digest}), flush=True)
        finally:
            browser.close()


if __name__ == '__main__':
    main()
