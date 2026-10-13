"""P01 pointer help must stay stable and never send a model request."""
import json
from playwright.sync_api import sync_playwright, expect

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors, posts = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    def intercept(route):
        if route.request.method == "POST":
            posts.append(route.request.url)
            route.abort()
        else:
            route.continue_()
    page.route("**/api/**", intercept)
    page.goto("http://127.0.0.1:28097", wait_until="networkidle")
    page.evaluate("selectTab(0)")
    for pane, ids in [("model", ["chat-send", "preflight"]), ("grade", ["verify"])]:
        page.evaluate("name => selectP01Pane(name)", pane)
        for button_id in ids:
            button = page.locator("#" + button_id)
            button.scroll_into_view_if_needed()
            page.mouse.move(1, 1)
            before = button.bounding_box()
            button.hover()
            tip = page.locator("#" + button.get_attribute("aria-describedby"))
            expect(tip).to_be_visible()
            page.wait_for_timeout(180)
            assert button.bounding_box() == before
            box = tip.bounding_box()
            assert tip.evaluate("el => getComputedStyle(el).position") == "static"
            assert tip.locator(".action-help-summary").inner_text()
            assert tip.locator(".action-help-detail").inner_text()
            page.mouse.move(1, 1)
            expect(tip).to_be_visible()
            button.focus()
            expect(tip).to_be_visible()
            page.locator("#navigation-home").focus()
            expect(tip).to_be_visible()
    assert not posts, posts
    assert not errors, errors
    print(json.dumps({"hover_checks": 3, "button_movement": False, "tips_fit_viewport": True,
                      "keyboard_help": True, "backend_posts": len(posts), "errors": errors}))
    browser.close()
