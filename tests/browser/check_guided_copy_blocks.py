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
    # 긴 코드는 페이지 높이만큼 펼치고 내부 세로 스크롤을 만들지 않습니다.
    expanded = page.evaluate("""() => {
      const block = document.createElement('div');
      block.className = 'copyable-block';
      const pre = document.createElement('pre');
      pre.textContent = Array.from({length: 80}, (_, i) => `line ${i}`).join(String.fromCharCode(10));
      block.append(pre);
      document.body.append(block);
      const style = getComputedStyle(pre);
      const result = {height: pre.getBoundingClientRect().height,
        scrollHeight: pre.scrollHeight, clientHeight: pre.clientHeight,
        maxHeight: style.maxHeight, overflowY: style.overflowY};
      block.remove();
      return result;
    }""")
    assert expanded["height"] > 360 and expanded["scrollHeight"] <= expanded["clientHeight"] + 1, expanded
    assert expanded["maxHeight"] == "none" and expanded["overflowY"] != "scroll", expanded
    admin = page.evaluate("""() => {
      const answer = document.createElement('div');
      answer.className = 'admin-answer-content';
      const pre = document.createElement('pre');
      pre.textContent = Array.from({length: 80}, (_, i) => `answer ${i}`).join(String.fromCharCode(10));
      answer.append(pre);
      document.body.append(answer);
      const style = getComputedStyle(answer);
      const result = {height: answer.getBoundingClientRect().height,
        scrollHeight: answer.scrollHeight, clientHeight: answer.clientHeight,
        maxHeight: style.maxHeight};
      answer.remove();
      return result;
    }""")
    assert admin["height"] > 360 and admin["scrollHeight"] <= admin["clientHeight"] + 1, admin
    assert admin["maxHeight"] == "none", admin
    disabled = context.new_page()

    def disabled_bootstrap(route):
        response = route.fetch()
        payload = response.json()
        payload["copyable_code_blocks"] = False
        route.fulfill(json=payload)

    disabled.route("**/api/bootstrap", disabled_bootstrap)
    disabled.goto(origin, wait_until="networkidle")
    disabled.evaluate('selectWorkspace("tutorial")')
    assert disabled.locator("#tutorial-submit-command").locator("..").get_attribute("class") != "copyable-block"
    assert disabled.locator(".copy-block-toolbar").count() == 0
    context.close()
    browser.close()
print("PASS: P00 curl command copies exactly; server-disabled blocks have no copy UI")
