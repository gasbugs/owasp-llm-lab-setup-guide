"""Browser display fixtures; no grading or model calls."""
from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 assert page.locator('#comparison').count()==0
 page.evaluate('selectTab(1,"P23")');page.locator('#h23-grade-tab').click()
 for index in range(2):
  page.evaluate('payload=>renderEnvelope(payload)',{'activity_id':'P23','course_verdict':'ERR','task_completed':False,'result':{'cases':[{'case_id':'normal','case_verified':True,'input':'<script>入力</script>','expected':{'provider_attempts':1},'response':{'reply':'actual'}},{'case_id':'blank','case_verified':True,'input':'   ','expected':{'error_type':'ValueError'},'error':{'type':'ValueError'}},{'case_id':'provider-error','case_verified':False,'expected':{'error_type':'RuntimeError'},'error':{'type':'NotImplementedError'}}]}})
  expect(page.locator('#case-results')).to_be_visible()
  expect(page.locator('.inspection')).to_be_hidden()
  assert page.locator('#case-results-list .case-card').count()==3
  assert page.locator('#case-results-list details[open]').count()==0
  expect(page.locator('#case-results-list .case-detail').first).to_be_hidden()
  page.locator('#case-results-list summary').first.click()
  expect(page.locator('#case-results-list .case-detail').first).to_be_visible()
  expect(page.locator('#case-results-list')).to_contain_text('入力')
  expect(page.locator('#case-results-list')).to_contain_text('期待'.replace('期待','기대 동작'))
  assert page.locator('#case-results-list script').count()==0
  assert page.locator('#case-results-list .case-badge').all_text_contents()==['PASS','PASS','ERR']
 page.locator('#h23-experience-tab').click();expect(page.locator('#case-results')).to_be_hidden()
 assert not errors,errors
 print('PASS: no historical comparison; current three cases visible for basic model mission; input/expected/result/error; no duplication; safe text')
 b.close()
