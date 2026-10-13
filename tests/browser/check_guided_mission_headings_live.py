from playwright.sync_api import sync_playwright, expect
import json
with sync_playwright() as p:
    browser=p.chromium.launch()
    page=browser.new_page(viewport={'width':1440,'height':1000})
    errors=[]; intercepted=[]
    page.on('pageerror',lambda error: errors.append(str(error)))
    def route_api(route):
        if route.request.method=='POST':
            intercepted.append(route.request.url)
            route.fulfill(status=503,content_type='application/json',body=json.dumps({'detail':'화면 회귀 검사: 실제 작업은 실행하지 않습니다.'}))
        else: route.continue_()
    page.route('**/api/**',route_api)
    page.goto('http://127.0.0.1:28097',wait_until='networkidle')
    for number in range(1,23):
        problem=f'P{number:02}'
        page.evaluate('(id) => selectTab(practiceGroups.findIndex(group => group.includes(id)), id)',problem)
        if number==1: page.evaluate('selectP01Pane("grade")')
        button=page.locator('#verify' if number==1 else f'#h{number:02}-verify')
        button.click()
        expect(button).to_be_enabled()
        assert page.locator('#current-station').inner_text()==problem
        assert page.locator('#activity-label').inner_text()=='PRACTICE · '+problem
        assert page.locator('#breadcrumb-current').inner_text().startswith(problem+' · ')
        assert page.locator('#activity-title').inner_text()==page.evaluate('(id)=>homeMissions.find(item=>item.id===id).title',problem)
        page.locator('#navigation-home').click()
    assert not errors,errors
    print(json.dumps({'execution_heading_checks':22,'posts_intercepted':len(intercepted),'backend_jobs_started':0,'page_errors':errors}))
    browser.close()
