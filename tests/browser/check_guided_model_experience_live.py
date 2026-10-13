import json
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
    browser=p.chromium.launch();page=browser.new_page(viewport={"width":1440,"height":1000})
    errors=[];calls=[]
    page.on("pageerror",lambda e:errors.append(str(e)))
    page.goto("http://127.0.0.1:28097",wait_until="networkidle")
    before=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    page.evaluate('selectTab(1,"P23")')
    page.locator('#h23-experience-tab').click()
    expect(page.locator('#h23-chat-input')).to_be_visible()
    expect(page.locator('#h23-verify')).to_be_hidden()
    payload={'graded':False,'reply':'<script>text only</script>','usage':{'inputTokens':3,'outputTokens':64},'stop_reason':'max_tokens'}
    def mock(route):
        calls.append(route.request.url)
        route.fulfill(status=200,content_type='application/json',body=json.dumps(payload))
    page.route('**/api/practice/P23/chat',mock)
    page.locator('#h23-chat-send').click()
    expect(page.locator('#h23-chat-reply')).to_have_text(payload['reply'])
    expect(page.locator('#h23-chat-meta')).to_contain_text('출력 한도')
    assert page.locator('#h23-chat-reply script').count()==0
    after=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    assert before==after
    page.locator('#h23-grade-tab').click()
    expect(page.locator('#h23-verify')).to_be_visible()
    expect(page.locator('#h23-experience')).to_be_hidden()
    page.evaluate('selectTab(1,"P02")')
    expect(page.locator('#h23-experience-tabs')).to_be_visible()
    page.locator('#h23-experience-tab').click()
    expect(page.locator('#mission-experience-run')).to_be_visible()
    expect(page.locator('#h23-chat-input')).to_be_hidden()
    assert len(calls)==1 and not errors,errors
    print('PASS: separate experience, actual learner endpoint, output cap cue, safe text display, unchanged grading history')
    browser.close()
