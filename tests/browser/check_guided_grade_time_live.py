from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('cacheGradingResult("P23",{activity_id:"P23",course_verdict:"ERR",task_completed:false,result:{}},Date.now()-1500);selectTab(1,"P23");selectModelCallPane("grade");void 0')
 before=page.locator('#grading-checked-at').inner_text();assert '한국시간' in before and '소요 1.5초' in before,before
 page.reload(wait_until='networkidle');page.evaluate('selectTab(1,"P23");selectModelCallPane("grade")');expect(page.locator('#grading-checked-at')).to_have_text(before)
 page.evaluate('cacheGradingResult("P00",{completed:false,feedback:"fixture"},Date.now()-1200);displayTutorialGrade(JSON.parse(sessionStorage.getItem("guided-grading-result-P00")));selectWorkspace("tutorial");selectTutorialPane("grade");void 0')
 p00=page.locator('#tutorial-checked-at').inner_text();assert '한국시간' in p00 and '소요 1.2초' in p00,p00
 page.reload(wait_until='networkidle');page.evaluate('selectWorkspace("tutorial");selectTutorialPane("grade")');expect(page.locator('#tutorial-checked-at')).to_have_text(p00)
 expect(page.locator('#completion-toast')).to_be_hidden()
 print('PASS: last grading receipt time and elapsed duration saved and restored for regular mission and P00; no celebration on reload')
 b.close()
