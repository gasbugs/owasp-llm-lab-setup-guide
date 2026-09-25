"""Exercise P17 through the actual proxy, Control Center and TCP verifier."""
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
            with page.expect_response(lambda response: response.url.endswith('/api/practice/P17/verify'),
                                      timeout=180000) as pending:
                page.locator('#h17-verify').click()
            response = pending.value
            assert response.status == 200
            result = response.json()
            complete = not args.incomplete
            assert result['activity_id'] == 'P17'
            assert result['task_completed'] is complete
            assert result['security_verdict'] == ('PASS' if complete else 'ERR')
            label = 'P17 과제: ' + ('완료' if complete else '미완료')
            page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
            rendered = json.loads(page.locator('#raw').inner_text())
            if rendered != result:
                args.output.with_suffix('.mismatch.json').write_text(json.dumps(
                    {'response': result, 'rendered': rendered}, ensure_ascii=False, indent=2))
            assert rendered == result
            execution = result['result']['execution']
            assert execution['source_digest'] == args.source_digest
            if execution.get('execution_error'):
                assert not complete
                assert execution['closed'] is False
            else:
                assert len(execution['cases']) == 3
            if complete:
                assert len(result['result']['products']) == 3
                assert [c['downstream_count'] for c in result['result']['cases']] == [1, 0, 0]
                assert result['result']['counter_delta'] == {'allow': 1, 'block': 2}
            else:
                assert result['result'].get('failed_requirement')
            boundary = page.evaluate('''async () => {
                const bootstrap = await (await fetch('/api/bootstrap')).json();
                const rejected = await fetch('/api/practice/P17/verify', {
                    method: 'POST', headers: {'X-CSRF-Token': bootstrap.csrf_token,
                    'Content-Type': 'application/json'}, body: JSON.stringify({task_completed: true})});
                return rejected.status;
            }''')
            assert boundary == 422
            assert errors == []
            page.screenshot(path=str(args.output.with_suffix('.png')))
            proof = {'scope': 'Browser→proxy→Control Center→P17→products→TCP verifier; no AWS',
                     'response': result, 'submitted_verdict_status': boundary,
                     'source_digest': args.source_digest, 'page_errors': errors}
            args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
            print(json.dumps({'scope': proof['scope'], 'task_completed': complete}), flush=True)
        finally:
            browser.close()


if __name__ == '__main__':
    main()
