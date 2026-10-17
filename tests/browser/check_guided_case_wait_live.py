"""UI progress fixtures, without model calls or grading writes."""
from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle');errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 pending=[];page.route('**/api/practice/P00/result',lambda route:pending.append(route))
 page.evaluate('selectWorkspace("tutorial")');page.locator('#tutorial-grade-tab').click();page.locator('#tutorial-grade-check').click()
 expect(page.locator('#tutorial-cases .case-running-bar')).to_have_count(4)
 expect(page.locator('#tutorial-cases .case-elapsed').first).to_have_text('대기 1초',timeout=5000)
 assert page.locator('#tutorial-cases progress[value]').count()==0
 expect(page.locator('#tutorial-grade-check')).to_be_disabled()
 pending.pop().fulfill(json={'completed':False,'cases':[{'case_id':'fixture','case_verified':False}],'feedback':'fixture','upstream_called':False})
 expect(page.locator('#tutorial-cases .case-running-bar')).to_have_count(0);expect(page.locator('#tutorial-grade-check')).to_be_enabled()
 page.evaluate('selectTab(0,"P01");selectP01Pane("grade");document.querySelector("#case-progress").hidden=false;renderCaseProgress({phase:"running",total:23,cases:[{case_id:"finished",status:"PASS",elapsed_seconds:0.5}],current_case:{number:2,case_id:"active",status:"실행 중",started_at:new Date(Date.now()-2000).toISOString()}});updateCaseElapsed()')
 expect(page.locator('#case-progress-list .case-running-bar')).to_have_count(1);expect(page.locator('#case-progress-list .case-elapsed').last).to_have_text('대기 2초')
 expect(page.locator('#case-progress-list .case-elapsed').first).to_have_text('0.5초')
 page.evaluate('renderCaseProgress({phase:"running",total:23,cases:[{case_id:"finished",status:"PASS",elapsed_seconds:0.5}],current_case:{number:2,case_id:"active",status:"실행 중",started_at:new Date(Date.now()-2000).toISOString()}})')
 assert int(page.locator('#case-progress-list .case-elapsed').last.inner_text().split(' ')[1][:-1]) >= 2
 expect(page.locator('#case-progress-list .case-elapsed').first).to_have_text('0.5초')
 assert not errors,errors
 print('PASS: P00 four pending bars and adjacent elapsed; no invented percentage; P01 redraw keeps active elapsed and completed duration; wait ends on response')
 b.close()
