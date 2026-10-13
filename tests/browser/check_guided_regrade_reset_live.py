"""Regrading clears previous UI cases immediately; no live grading or AWS calls."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto("http://127.0.0.1:28097", wait_until="networkidle")
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    for problem, tab in (("P23", 1), ("P01", 0)):
        page.evaluate("""([problem, tab]) => {
          const payload = {activity_id:problem, course_verdict:"PASS", task_completed:true,
            result:{cases:[{case_id:"OLD-CASE", status:"PASS"}]}};
          cacheGradingResult(problem,payload,Date.now()-1000);
          selectTab(tab,problem);
          if(problem==="P01") selectP01Pane("grade"); else selectModelCallPane("grade");
        }""", [problem, tab])
        expect(page.locator("#case-results-list")).to_contain_text("OLD-CASE")
        pending = []
        page.route(f"**/api/practice/{problem}/verify", lambda route: pending.append(route))
        if problem == "P01":
            page.route("**/api/test-progress/P01", lambda route: route.fulfill(json={"phase":"idle", "cases":[], "total":23}))
        page.locator("#verify" if problem == "P01" else "#h23-verify").click()
        expect(page.locator("#case-results-list .test-case")).to_have_count(0)
        assert page.locator("#case-results-list").inner_text() == ""
        expect(page.locator("#case-results")).to_be_hidden()
        expect(page.locator("#grading-checked-at")).to_be_hidden()
        assert not page.evaluate("problem => missionResults.has(problem)", problem)
        assert page.evaluate("problem => sessionStorage.getItem(`guided-grading-result-${problem}`)", problem) is None
        pending.pop().fulfill(json={"activity_id":problem,"course_verdict":"ERR","task_completed":False,
             "result":{"cases":[{"case_id":"NEW-CASE","status":"ERR"}]}})
        expect(page.locator("#case-results-list")).to_contain_text("NEW-CASE")
        expect(page.locator("#case-results-list")).not_to_contain_text("OLD-CASE")
    page.evaluate('cacheGradingResult("P00",{completed:false,cases:[{case_id:"OLD-TUTORIAL",case_verified:false}]},Date.now());displayTutorialGrade(JSON.parse(sessionStorage.getItem("guided-grading-result-P00")));selectWorkspace("tutorial");selectTutorialPane("grade")')
    pending = []
    page.route("**/api/practice/P00/result", lambda route: pending.append(route))
    page.locator("#tutorial-grade-check").click()
    expect(page.locator("#tutorial-cases")).not_to_contain_text("OLD-TUTORIAL")
    expect(page.locator("#tutorial-cases .case-running-bar")).to_have_count(4)
    expect(page.locator("#tutorial-checked-at")).to_have_text("이번 채점을 진행하고 있습니다.")
    pending.pop().fulfill(json={"completed":False,"cases":[],"feedback":"fixture","upstream_called":False})
    expect(page.locator("#tutorial-grade-check")).to_be_enabled()
    assert not errors, errors
    print("PASS: P23/P01/P00 regrading removes old cases, cache and timestamp before response; new cases replace old ones")
    browser.close()
