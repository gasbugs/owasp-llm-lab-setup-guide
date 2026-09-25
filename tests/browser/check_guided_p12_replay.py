"""Replay actual P12 TCP envelopes in the browser; not a live grading test."""
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
    parser.add_argument('starter', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    passed = json.loads(args.passed.read_text())['envelope']
    starter = json.loads(args.starter.read_text())['envelope']
    assert passed['task_completed'] is True and starter['task_completed'] is False
    error = {'activity_id': 'P12', 'task_completed': False, 'security_verdict': 'ERR',
             'course_verdict': 'ERR', 'reason': '검증 응답을 받지 못했습니다.',
             'next_check': '같은 실행의 서비스 기록을 확인하세요.', 'downstream_called': None}
    cases, calls = [passed, starter, error], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, body, kind='application/json'):
            self.send_response(200)
            self.send_header('Content-Type', kind)
            self.end_headers()
            self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

        def do_GET(self):
            if self.path == '/api/bootstrap':
                return self.send({'csrf_token': 'replay', 'official_uis': []})
            files = {'/': ('index.html', 'text/html; charset=utf-8'),
                     '/app.js': ('app.js', 'text/javascript'), '/app.css': ('app.css', 'text/css')}
            if self.path not in files:
                self.send_error(404)
                return
            name, kind = files[self.path]
            self.send((ROOT / name).read_bytes(), kind)

        def do_POST(self):
            assert self.path == '/api/practice/P12/verify'
            assert self.headers['X-CSRF-Token'] == 'replay'
            assert int(self.headers.get('Content-Length', '0')) == 0
            result = cases[len(calls)]
            calls.append(self.path)
            self.send(result)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={'width': 1440, 'height': 1000}, color_scheme='dark')
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(origin + '/') else route.abort())
                page.goto(origin, wait_until='networkidle')
                page.locator('.tab[data-tab-index="6"]').click()
                assert page.locator('html').get_attribute('data-theme') == 'dark'
                problem = page.locator('#h12-work').inner_text()
                assert 'async handle_request(request, services)' in problem
                assert 'SQLite' in problem and 'HTTP 200일 때만' not in problem
                for index, expected in enumerate(cases):
                    page.locator('#h12-verify').click()
                    page.wait_for_function('(reason) => JSON.parse(document.querySelector("#raw").textContent).reason === reason', arg=expected['reason'])
                    raw = json.loads(page.locator('#raw').inner_text())
                    assert raw == expected
                    assert page.locator('#task-completion').inner_text() == 'P12 과제: ' + ('완료' if expected['task_completed'] else '미완료')
                    assert page.locator('#effective-label').inner_text() == '확인한 모델 호출'
                    assert page.locator('#forwarded-max').inner_text() == ('16' if index == 0 else '—')
                    assert page.locator('#requested-max').inner_text() == ('8' if index == 0 else '0' if index == 1 else '—')
                for width in (1440, 390):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    page.locator('#h12-verify').focus()
                    page.locator('#h12-verify-help').wait_for(state='visible')
                    assert page.evaluate('''() => {
                        const box = document.querySelector('#h12-verify-help').getBoundingClientRect();
                        const work = document.querySelector('.workbench').getBoundingClientRect();
                        return box.left >= Math.max(0, work.left) - 1
                          && box.right <= Math.min(innerWidth, work.right) + 1
                          && document.documentElement.scrollWidth <= innerWidth;
                    }''')
                    trigger = page.locator('[aria-controls="h12-verify-help"]')
                    trigger.click()
                    assert trigger.get_attribute('aria-expanded') == 'true'
                    trigger.press('Escape')
                    assert trigger.get_attribute('aria-expanded') == 'false'
                    page.screenshot(path=str(args.output.with_suffix(f'.{width}.png')))
                page.locator('[data-theme-choice="light"]').click()
                assert page.locator('html').get_attribute('data-theme') == 'light'
                assert not errors and len(calls) == 3
                result = {'scope': 'UI replay of actual P12 TCP results; not live Browser grading',
                          'requests': 3, 'widths': [1440, 390], 'missing_counts_not_zero': True,
                          'page_errors': errors}
                args.output.write_text(json.dumps(result, indent=2))
                print(json.dumps(result))
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == '__main__':
    main()
