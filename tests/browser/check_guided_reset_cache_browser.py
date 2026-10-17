"""Reset generation clears stale grading cache without reload loops."""
import os
from playwright.sync_api import sync_playwright

origin = os.environ["GUIDED_UI_BASE_URL"]
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto(origin, wait_until="networkidle")
    page.evaluate("""() => {
      sessionStorage.setItem('guided-reset-generation', 'stale-generation');
      sessionStorage.setItem('guided-grading-result-P00', JSON.stringify({completed:true}));
    }""")
    page.reload(wait_until="networkidle")
    assert page.evaluate("sessionStorage.getItem('guided-grading-result-P00')") is None
    assert page.locator("#home-completed").inner_text().strip().startswith("0")

    blocked = browser.new_page()
    navigations = []
    blocked.on("framenavigated", lambda frame: navigations.append(frame.url) if frame == blocked.main_frame else None)
    blocked.add_init_script("Object.defineProperty(window, 'sessionStorage', {get(){throw Error('disabled')}})")
    blocked.goto(origin, wait_until="networkidle")
    blocked.wait_for_timeout(800)
    assert len(navigations) == 1, navigations
    assert blocked.locator("#home-completed").inner_text().strip().startswith("0")
    browser.close()
print("PASS: stale grading cache cleared; disabled sessionStorage has no reload loop")
