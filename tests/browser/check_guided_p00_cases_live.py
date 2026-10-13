"""P00 case display fixtures; server validation is covered by unit tests."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 cases=[{'case_id':name,'case_verified':True,'expected':'fixture expected','actual':'fixture actual'} for name in ['JSON 객체 형식','필드 이름과 개수','질문 문장','출력 상한의 자료형과 값']]
 page.route('**/api/practice/P00/result',lambda r:r.fulfill(json={'completed':True,'cases':cases,'received':{'message':'fixture','max_tokens':64},'feedback':'네 가지 요청 검사를 통과했습니다.','upstream_called':False}))
 page.evaluate('selectWorkspace("tutorial")');page.locator('#tutorial-grade-tab').click();expect(page.locator('#tutorial-cases .case-card')).to_have_count(4);page.evaluate('displayTutorialGrade({completed:true})');expect(page.locator('#tutorial-cases')).to_contain_text('재제출 필요');assert page.locator('#tutorial-cases .case-badge').all_text_contents()==['재제출 필요']*4;page.locator('#tutorial-experience-tab').click();page.locator('#tutorial-check').click();expect(page.locator('#tutorial-cases')).to_be_hidden()
 page.locator('#tutorial-grade-tab').click();page.locator('#tutorial-grade-check').click();expect(page.locator('#tutorial-cases .case-card')).to_have_count(4)
 assert page.locator('#tutorial-cases .case-badge').all_text_contents()==['PASS']*4
 assert page.locator('#tutorial-cases details[open]').count()==0
 page.locator('#tutorial-cases summary').first.click();expect(page.locator('#tutorial-cases .case-detail').first).to_be_visible()
 page.reload(wait_until='networkidle');page.evaluate('selectWorkspace("tutorial")');page.locator('#tutorial-grade-tab').click();expect(page.locator('#tutorial-cases .case-card')).to_have_count(4)
 expect(page.locator('#completion-toast')).to_be_hidden()
 print('PASS P00: four actual-check display cards, grade pane only, collapsed details, reload without celebration')
 b.close()
