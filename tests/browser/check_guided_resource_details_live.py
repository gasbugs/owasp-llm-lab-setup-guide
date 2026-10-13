from playwright.sync_api import sync_playwright, expect
import json
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('selectTab(1,"P02");selectModelCallPane("experience")')
 response=page.request.get('http://127.0.0.1:28097/api/resource-status/P02',timeout=180000)
 assert response.status==200,response.text()
 payload=response.json();assert payload['read_only'] is True
 print('Live AWS inventory:',payload['state'],[(r['type'],list(r.get('facts',{})),r.get('inspection_error')) for r in payload['resources']])
 page.route('**/api/resource-status/P02',lambda route:route.fulfill(content_type='application/json',body=json.dumps(payload)))
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':1000})
  group=page.locator('#mission-resource-actions section[data-problem="P02"]')
  group.get_by_role('button',name='AWS 자원 상태 확인').click()
  expect(group.locator('.aws-resource-row')).to_have_count(len(payload['resources']))
  assert not group.locator('.aws-status-details').evaluate('e=>e.open')
  group.locator('.aws-status-details>summary').click()
  assert page.locator('#resource-operation').evaluate('(e)=>e.previousElementSibling.classList.contains("aws-resource-toolbar")')
  assert not group.get_by_text('RAW 응답 전체',exact=True).locator('..').evaluate('e=>e.open')
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 print('PASS: live AWS read-only detail values rendered as collapsed vertical list, adjacent progress, desktop/mobile without overflow')
 b.close()
