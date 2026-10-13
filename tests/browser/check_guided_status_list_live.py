from playwright.sync_api import sync_playwright,expect
import json
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle');page.evaluate('selectTab(1,"P02");selectModelCallPane("experience")')
 payload={'practice_id':'P02','read_only':True,'state':'partial','checked_at':'2026-10-10T00:00:00Z','resources':[{'type':'S3 source bucket','name':'owned-source','state':'present','console_url':'https://us-east-1.console.aws.amazon.com/s3/buckets/owned-source?region=us-east-1','facts':{'문서 수':'2개'}},{'type':'Knowledge Base','name':'kb-id','state':'absent'},{'type':'Data source','name':'ds-id','state':'present','facts':{'최근 동기화':'FAILED'}}]}
 page.route('**/api/resource-status/P02',lambda route:route.fulfill(content_type='application/json',body=json.dumps(payload)))
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':1000});group=page.locator('#mission-resource-actions section[data-problem="P02"]')
  group.get_by_role('button',name='AWS 자원 상태 확인').click();details=group.locator('.aws-status-details');expect(details).to_be_visible();assert not details.evaluate('e=>e.open')
  expect(group.locator('.aws-resource-list')).to_be_hidden();details.locator('> summary').click();expect(group.locator('.aws-resource-list')).to_be_visible()
  rows=group.locator('.aws-resource-row');assert rows.count()==3
  expect(rows.nth(0).get_by_role('link',name='AWS에서 확인 ↗')).to_be_visible()
  size=details.locator('> summary').evaluate('e=>parseFloat(getComputedStyle(e).fontSize)')
  assert details.locator('.aws-resource-row strong,.aws-resource-row code,.aws-resource-row dt,.aws-resource-row dd,.aws-resource-row a').evaluate_all('(els,size)=>els.every(e=>parseFloat(getComputedStyle(e).fontSize)<=size)',size)
  expect(rows.nth(0)).to_contain_text('확인됨');expect(rows.nth(1)).to_contain_text('미생성')
  assert rows.nth(0).locator('strong').get_attribute('class')=='aws-status-healthy'
  for n in (1,2):assert rows.nth(n).locator('strong').get_attribute('class')=='aws-status-problem'
  bounds=rows.evaluate_all('els=>els.map(e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,bottom:r.bottom}})')
  assert all(bounds[n+1]['y']>=bounds[n]['bottom'] and bounds[n+1]['x']==bounds[n]['x'] for n in range(2))
  assert not details.get_by_text('RAW 응답 전체',exact=True).locator('..').evaluate('e=>e.open')
  assert page.locator('#resource-operation').evaluate('e=>e.previousElementSibling.classList.contains("aws-resource-toolbar")')
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 print('PASS: collapsed result, top-to-bottom list, green present/red missing and failed sync, adjacent progress desktop/mobile')
 b.close()
