from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
    browser=p.chromium.launch()
    page=browser.new_page(viewport={"width":1440,"height":1000})
    errors=[]
    page.on("pageerror",lambda e:errors.append(str(e)))
    page.goto("http://127.0.0.1:28097",wait_until="networkidle")
    assert page.locator("#home-missions .home-mission").count()==24
    assert page.evaluate('practiceGroups[1]')==["P23","P02","P03"]
    assert page.evaluate('missionLabel("P23")')=="P01-01"
    assert page.evaluate('missionLabel("P02")')=="P01-02"
    assert page.evaluate('missionLabel("P03")')=="P01-03"
    page.evaluate('selectTab(1,"P23")')
    expect(page.locator("#h23-work")).to_be_visible()
    expect(page.locator("#h02-work")).to_be_hidden()
    expect(page.locator("#h23-verify")).to_be_visible()
    expect(page.locator("#activity-title")).to_have_text("첫 질문을 Nova Lite까지!")
    bootstrap=page.evaluate('fetch("/api/bootstrap").then(r=>r.json())')
    forged=page.evaluate('csrf => fetch("/api/practice/P23/verify",{method:"POST",headers:{"X-CSRF-Token":csrf,"Content-Type":"application/json"},body:JSON.stringify({task_completed:true})}).then(r=>r.status)',bootstrap['csrf_token'])
    assert forged==422
    page.locator("#h23-verify").click()
    expect(page.locator("#raw")).to_contain_text('"task_completed": false',timeout=20000)
    expect(page.locator("#case-results-list .case-card")).to_have_count(3)
    assert not errors,errors
    print("PASS: model call first, KB second/third, isolated mission, 23 total")
    browser.close()
