"""Verify server-owned copy controls without submitting learner work."""
import os
from playwright.sync_api import sync_playwright

origin = os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097")
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    context = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
    page = context.new_page()
    page.goto(origin, wait_until="networkidle")
    page.evaluate('selectWorkspace("tutorial")')
    block = page.locator("#tutorial-submit-command").locator("..")
    assert block.get_attribute("class") == "copyable-block"
    assert block.locator(".copy-block-toolbar span").inner_text() == "curl 요청"
    command = block.locator("pre").inner_text()
    assert "curl -sS -X POST" in command and "Bearer " in command
    block.locator(".copy-block-button").click()
    assert page.evaluate("navigator.clipboard.readText()") == command
    assert page.locator(".copy-block-toolbar span").filter(has_text="코드 블록").count() == 0
    context.close()
    browser.close()
print("PASS: P00 curl command is titled and copied exactly; generic code-block title absent")
