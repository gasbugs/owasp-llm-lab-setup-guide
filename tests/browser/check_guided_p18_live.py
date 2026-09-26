"""Exercise actual P18 product queries via Browser, proxy, CC and TCP verifier."""
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
                if response.status == 200:
                    break
        except (URLError, TimeoutError):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError('Control Center behind proxy did not become ready')
        time.sleep(0.5)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, color_scheme='dark')
            page.route('**/*', lambda route: route.continue_()
                       if route.request.url.startswith(origin + '/') else route.abort())
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin, wait_until='networkidle')
            page.locator('.tab[data-tab-index="10"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            problem = page.locator('#h18-work').inner_text()
            assert 'P18' in problem and 'queries.yaml' in problem
            examples = '\n'.join(page.locator('#h18-work pre').all_text_contents())
            assert 'logql:' not in examples and 'sum by (' not in examples
            with page.expect_response(lambda response: response.url.endswith('/api/practice/P18/verify'),
                                      timeout=180000) as pending:
                page.locator('#h18-verify').click()
            response = pending.value
            assert response.status == 200
            result = response.json()
            # Persist before assertions so a live failure can be diagnosed without replaying requests.
            args.output.with_suffix('.response.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
            complete = not args.incomplete
            assert result['activity_id'] == 'P18'
            assert result['task_completed'] is complete
            assert result['security_verdict'] == ('PASS' if complete else 'ERR')
            label = 'P18 과제: ' + ('완료' if complete else '미완료')
            page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
            assert json.loads(page.locator('#raw').inner_text()) == result
            assert result['result']['source_digest'] == args.source_digest
            if complete:
                cases = result['result']['cases']
                assert len(cases) == 2
                assert [case['decision'] for case in cases] == ['allow', 'block']
                assert all(case['counter_delta'] == {'allow': 1, 'block': 1} for case in cases)
                assert all(case['logs'] == 1 for case in cases)
                assert 'notice_lookup' in cases[0]['spans']
                assert 'notice_lookup' not in cases[1]['spans']
                assert len(result['result']['query_attempts']) == 2
            else:
                assert result['result'].get('failed_requirement') or result.get('reason')
            boundary = page.evaluate('''async () => {
                const bootstrap = await (await fetch('/api/bootstrap')).json();
                const rejected = await fetch('/api/practice/P18/verify', {
                    method: 'POST', headers: {'X-CSRF-Token': bootstrap.csrf_token,
                    'Content-Type': 'application/json'}, body: JSON.stringify({task_completed: true})});
                return rejected.status;
            }''')
            assert boundary == 422
            sizes = []
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                page.locator('#h18-verify').focus()
                page.locator('#h18-help').wait_for(state='visible')
                assert page.evaluate('''() => {
                    const tip = document.querySelector('#h18-help').getBoundingClientRect();
                    const work = document.querySelector('.workbench').getBoundingClientRect();
                    return tip.left >= Math.max(0, work.left) - 1
                        && tip.right <= Math.min(innerWidth, work.right) + 1
                        && document.documentElement.scrollWidth <= innerWidth;
                }'''), f'tooltip or page overflows at {width}px'
                help_button = page.locator('[aria-describedby="h18-help"]')
                help_button.focus()
                assert help_button.evaluate("(button) => button.closest('.action-control').classList.contains('tip-dismissed')") is False
                help_button.press('Escape')
                assert help_button.evaluate("(button) => button.closest('.action-control').classList.contains('tip-dismissed')") is True
                help_button.evaluate("(button) => button.blur()")
                page.locator('#h18-work').scroll_into_view_if_needed()
                page.screenshot(path=str(args.output.with_suffix(f'.{width}.png')))
                sizes.append(width)
            page.locator('[data-theme-choice="light"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'light'
            page.locator('[data-theme-choice="dark"]').click()
            assert page.locator('html').get_attribute('data-theme') == 'dark'
            assert errors == []
            proof = {'scope': 'Browser→proxy→CC→P18→actual products→TCP verifier; no AWS',
                     'response': result, 'submitted_verdict_status': boundary,
                     'source_digest': args.source_digest, 'page_errors': errors,
                     'viewports': sizes, 'keyboard_mobile_tooltip': True, 'system_manual_theme': True}
            args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
            print(json.dumps({'scope': proof['scope'], 'task_completed': complete}), flush=True)
        finally:
            browser.close()


if __name__ == '__main__':
    main()
