"""UI replay of measured P19 evidence and a synthetic transport error, not live grading."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-control-center'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('passed', type=Path)
    parser.add_argument('failed', type=Path)
    parser.add_argument('screenshot', type=Path)
    args = parser.parse_args()
    passed = json.loads(args.passed.read_text())['http_verification']
    failed = json.loads(args.failed.read_text())['http_verification']
    assert passed['task_completed'] is True and failed['task_completed'] is False
    calls = []
    error = {'activity_id': 'P19', 'task_completed': False, 'security_verdict': 'ERR',
             'course_verdict': 'ERR', 'reason': '검증 응답을 받지 못했습니다.',
             'next_check': '검증기 컨테이너의 실행 상태를 확인합니다.'}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, payload, status=200, kind='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.end_headers()
            self.wfile.write(payload if isinstance(payload, bytes) else json.dumps(payload).encode())

        def do_GET(self):
            if self.path == '/api/bootstrap':
                return self.send({'csrf_token': 'replay-only', 'official_uis': []})
            files = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                     '/app.css': ('app.css', 'text/css')}
            if self.path not in files:
                return self.send({}, 404)
            name, kind = files[self.path]
            self.send((ROOT / name).read_bytes(), kind=kind)

        def do_POST(self):
            assert self.path == '/api/practice/P19/verify'
            assert self.headers['X-CSRF-Token'] == 'replay-only'
            assert int(self.headers.get('Content-Length', '0')) == 0
            calls.append(self.path)
            if len(calls) == 3:
                return self.send({'detail': error}, 502)
            self.send(passed if len(calls) == 1 else failed)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    try:
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
                problem = page.locator('#h19-work').inner_text()
                assert 'analyze_incident' in problem and 'JOIN_KEY' not in problem
                assert 'def analyze_incident' not in problem
                for expected, completed in ((passed, True), (failed, False), (error, False)):
                    page.locator('#h19-verify').click()
                    label = 'P19 과제: ' + ('완료' if completed else '미완료')
                    page.wait_for_function('(label) => document.querySelector("#task-completion").textContent === label', arg=label)
                    # A repeated incomplete label is insufficient: wait for the new raw result.
                    page.wait_for_function('(reason) => JSON.parse(document.querySelector("#raw").textContent).reason === reason', arg=expected.get('reason'))
                    raw = json.loads(page.locator('#raw').inner_text())
                    for key, value in expected.items():
                        assert raw[key] == value
                for width in (1440, 390):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    page.locator('#h19-verify').focus()
                    page.locator('#h19-help').wait_for(state='visible')
                    assert page.evaluate('''() => {
                        const box = document.querySelector('#h19-help').getBoundingClientRect();
                        const work = document.querySelector('.workbench').getBoundingClientRect();
                        return box.left >= Math.max(0, work.left) - 1
                          && box.right <= Math.min(innerWidth, work.right) + 1
                          && document.documentElement.scrollWidth <= innerWidth;
                    }''')
                    help_button = page.locator('[aria-controls="h19-help"]')
                    help_button.click()
                    assert help_button.get_attribute('aria-expanded') == 'true'
                    help_button.press('Escape')
                    assert help_button.get_attribute('aria-expanded') == 'false'
                page.locator('[data-theme-choice="light"]').click()
                assert page.locator('html').get_attribute('data-theme') == 'light'
                page.locator('#h19-work').scroll_into_view_if_needed()
                page.screenshot(path=str(args.screenshot))
                assert errors == [] and len(calls) == 3
                print(json.dumps({'scope': 'UI replay, not live grading', 'requests': 3,
                                  'widths': [1440, 390], 'transport_error_incomplete': True}))
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == '__main__':
    main()
