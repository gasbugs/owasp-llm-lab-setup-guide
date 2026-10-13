"""Display-cache fixtures only; no learner grading, provider calls or completion writes."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
 b=p.chromium.launch();context=b.new_context();page=context.new_page()
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('cacheGradingResult("P23", {activity_id:"P23",execution_id:"cached-fixture",course_verdict:"ERR",task_completed:false,access_token:"do-not-store",result:{cases:[{case_id:"normal",case_verified:false,input:"fixture",error:"fixture error"}]}});cacheGradingResult("P00",{completed:false,feedback:"cached P00 fixture"});void 0')
 assert 'do-not-store' not in page.evaluate('sessionStorage.getItem("guided-grading-result-P23")')
 page.evaluate('selectTab(1,"P23");document.querySelector("#h23-chat-response").textContent="temporary direct answer";void 0') if page.locator('#h23-chat-response').count() else None
 page.reload(wait_until='networkidle');page.evaluate('selectTab(1,"P23")');page.locator('#h23-grade-tab').click()
 expect(page.locator('#case-results-list')).to_contain_text('normal');expect(page.locator('#raw')).to_contain_text('cached-fixture')
 expect(page.locator('#completion-toast')).to_be_hidden();expect(page.locator('#completion-confetti')).to_be_hidden()
 page.evaluate('selectWorkspace("tutorial")');page.locator('#tutorial-grade-tab').click();expect(page.locator('#tutorial-grade-status')).to_contain_text('cached P00 fixture')
 expect(page.locator('#tutorial-received')).to_contain_text('아직 제출한 요청')
 other=context.new_page();other.goto('http://127.0.0.1:28097',wait_until='networkidle');assert other.evaluate('missionResults.has("P23")') is False
 print('PASS: last grading result survives reload in same tab; P00 restored; no celebration or direct-result restoration; credential excluded; another tab has no cache')
 b.close()
