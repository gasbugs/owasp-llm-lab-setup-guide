"""Session recovery UI fixtures; no grading or AWS requests."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
    browser=p.chromium.launch()
    page=browser.new_page()
    errors=[]
    page.on('pageerror',lambda e: errors.append(str(e)))
    page.goto('http://127.0.0.1:28097',wait_until='networkidle')
    bootstrap=page.evaluate('async () => (await fetch("/api/bootstrap")).json()')
    cookie=next(c for c in page.context.cookies() if c['name']=='guided_session')
    assert cookie['expires']>__import__('time').time()+600000
    page.evaluate('selectTab(1,"P02"); selectModelCallPane("experience")')
    page.locator('#document-upload-title').fill('입력 보존 확인')
    page.locator('#document-upload-body').fill('세션 재연결 중에도 작성한 문서 내용은 유지되어야 합니다.')
    calls=[]
    def refresh(route):
        calls.append(route.request.url)
        route.fulfill(status=401 if len(calls)==1 else 200,json={'refresh_after_seconds':60})
    page.route('**/api/session/refresh',refresh)
    bootstrap.update(csrf_token='refreshed-browser-fixture',p00_submission_token='refreshed-submission-fixture')
    page.route('**/api/bootstrap',lambda route: route.fulfill(json=bootstrap))
    page.evaluate('sessionCheckedAt=0; executionPending=true')
    page.evaluate('refreshBrowserSession()')
    assert not calls
    page.evaluate('executionPending=false; document.dispatchEvent(new Event("visibilitychange"))')
    expect(page.locator("#tutorial-submit-command")).to_contain_text("refreshed-submission-fixture")
    page.evaluate("async () => { if(sessionRefreshPromise) await sessionRefreshPromise; }")
    assert len(calls)==2
    expect(page.locator('#document-upload-title')).to_have_value('입력 보존 확인')
    expect(page.locator('#document-upload-body')).to_have_value('세션 재연결 중에도 작성한 문서 내용은 유지되어야 합니다.')
    assert page.evaluate('activeProblem')=='P02'
    expect(page.locator('#tutorial-submit-command')).to_contain_text('refreshed-submission-fixture')
    page.evaluate('refreshBrowserSession()')
    assert len(calls)==2
    assert not errors,errors
    print('PASS: persistent browser cookie, busy deferral, automatic visibility reconnect, current mission and inputs retained, P00 token updated, throttled renewal; no grading/AWS calls')
    browser.close()
