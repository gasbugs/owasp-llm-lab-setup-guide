from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.route('**/api/practice/P00/result',lambda r:r.fulfill(json={'completed':True,'received':{'message':'fixture','max_tokens':64},'feedback':'검사 완료','upstream_called':False}))
 page.evaluate('selectWorkspace("tutorial");p00Completed=false;window.celebrationCalls=[];celebratePractice=id=>window.celebrationCalls.push(id);void 0')
 page.locator('#tutorial-check').click();expect(page.locator('#tutorial-received')).to_contain_text('fixture');assert page.evaluate('celebrationCalls.length')==0;assert page.evaluate('p00Completed') is False;expect(page.locator('#tutorial-status')).not_to_contain_text('미션 완료')
 page.locator('#tutorial-grade-tab').click();page.locator('#tutorial-grade-check').click();expect(page.locator('#tutorial-grade-status')).to_contain_text('미션 완료');page.wait_for_function('celebrationCalls.length===1')
 page.locator('#tutorial-grade-check').click();page.wait_for_function('celebrationCalls.length===2');expect(page.locator('#tutorial-grade-panel')).to_be_visible()
 print('PASS: direct preview no celebration; grade-result check celebrates each successful click')
 b.close()
