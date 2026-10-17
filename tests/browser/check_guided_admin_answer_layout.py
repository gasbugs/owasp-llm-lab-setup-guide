"""Check the administrator answer layout with read-only browser fixtures."""
import os
from playwright.sync_api import sync_playwright

origin = os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097")
answer = "## 정답 코드\n\n```python\n" + "result = 'wide answer'\n" * 12 + "```\n"

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    for width in (1440, 390):
        page = browser.new_page(viewport={"width": width, "height": 900})
        writes = []
        page.on("request", lambda request: writes.append(request.url) if request.method == "POST" else None)

        def bootstrap(route):
            response = route.fetch()
            payload = response.json()
            payload["admin_mode"] = True
            route.fulfill(json=payload)

        page.route("**/api/bootstrap", bootstrap)
        page.route("**/api/admin/answers/*", lambda route: route.fulfill(json={"answer": answer}))
        page.goto(origin, wait_until="networkidle")
        for problem, command in (("P00", 'selectWorkspace("tutorial")'),
                                 ("P01", 'selectTab(0,"P01")')):
            page.evaluate(command)
            panel = page.locator("details.admin-answer:visible")
            assert panel.count() == 1, (width, problem)
            assert panel.locator("..").get_attribute("class").find("work-body") >= 0
            panel_box = panel.bounding_box()
            body_box = panel.locator("..").bounding_box()
            assert panel_box["width"] >= body_box["width"] - 45, (width, problem, panel_box, body_box)
            panel.locator("summary").click()
            assert panel.locator(".admin-answer-content pre").count() == 1
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, problem)
        assert not writes, writes
        page.close()
    browser.close()
print("PASS: P00/P01 admin answers span both columns at desktop/mobile without page overflow or writes")
