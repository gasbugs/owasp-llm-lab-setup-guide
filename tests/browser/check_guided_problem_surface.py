"""Render all Practice tabs without running learner code, providers, or grading."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-control-center"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            files = {"/": ("index.html", "text/html; charset=utf-8"),
                     "/app.js": ("app.js", "text/javascript"), "/app.css": ("app.css", "text/css")}
            if self.path == "/api/bootstrap":
                body = json.dumps({"csrf_token": "render-only", "official_uis": []}).encode()
                kind = "application/json"
            elif self.path in files:
                name, kind = files[self.path]
                body = (ROOT / name).read_bytes()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            requests.append(self.path)
            self.send_error(405)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    evidence = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(color_scheme="dark")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.route("**/*", lambda route: route.continue_()
                           if route.request.url.startswith(origin + "/") else route.abort())
                page.goto(origin, wait_until="networkidle")
                assert page.locator(".tab").count() == 13
                assert page.title() == "클씨랩 LLM 보안 실습실"
                assert "TENANT 03" not in page.locator("body").inner_text()
                assert page.locator(".help-trigger").count() == 0
                tooltip_checks = 0
                for width in (1440, 760, 390, 320):
                    page.set_viewport_size({"width": width, "height": 1000})
                    for index in range(13):
                        page.locator(f'.tab[data-tab-index="{index}"]').click()
                        assert page.locator(".lab-workspace:visible").count() >= 1
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, index)
                        for help_button in page.locator(".lab-workspace:visible .action-control > button[aria-describedby]").all():
                            tooltip = help_button.locator("..").locator(".action-tooltip")
                            if width <= 760:
                                tooltip.wait_for(state="visible")
                                assert tooltip.evaluate("el => getComputedStyle(el).position") == "static"
                            help_button.focus()
                            tooltip.wait_for(state="visible")
                            box = tooltip.bounding_box()
                            assert box and box["x"] >= 0 and box["x"] + box["width"] <= width, (width, index, box)
                            tooltip_checks += 1
                            help_button.press("Escape")
                            tooltip.wait_for(state="visible" if width <= 760 else "hidden")
                        for text in page.locator(".lab-workspace:visible pre").all_inner_texts():
                            assert text.startswith("docker compose ") or text.lstrip().startswith("{"), text[:80]
                        evidence.append({"width": width, "tab": index + 1})
                    page.screenshot(path=str(args.output.with_suffix(f".{width}.png")))
                assert not requests and not errors
                touch = browser.new_page(viewport={"width": 390, "height": 1000}, is_mobile=True, has_touch=True)
                touch.goto(origin, wait_until="networkidle")
                touch_posts = []
                def intercept_action(route):
                    touch_posts.append(route.request.url)
                    route.fulfill(status=503, content_type="application/json", body='{"detail":"touch-test-only"}')
                touch.route("**/api/provider-preflight", intercept_action)
                tip = touch.locator("#preflight").locator("..").locator(".action-tooltip")
                tip.wait_for(state="visible")
                tip.tap()
                assert not touch_posts and not requests
                touch.locator("#preflight").tap()
                touch.wait_for_timeout(100)
                assert len(touch_posts) == 1 and not requests
                touch.close()
                args.output.write_text(json.dumps({"scope": "problem surface rendering only; no grading or AWS",
                    "tabs_checked": evidence, "tooltip_checks": tooltip_checks,
                    "touch_help_actions": 0, "touch_button_intercepted_actions": len(touch_posts),
                    "post_requests": requests, "page_errors": errors}, indent=2))
                print(json.dumps({"views": len(evidence), "tooltip_checks": tooltip_checks,
                    "post_requests": len(requests), "page_errors": errors}))
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
