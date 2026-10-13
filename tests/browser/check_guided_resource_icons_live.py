from playwright.sync_api import sync_playwright, expect
import json
with sync_playwright() as p:
 b=p.chromium.launch(); page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':1000})
  for mission in ('P02','P03','P04'):
   page.evaluate('(id)=>{selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);selectModelCallPane("experience");}',mission)
   toolbar=page.locator(f'#mission-resource-actions section[data-problem="{mission}"] .aws-resource-toolbar')
   expect(toolbar).to_be_visible();assert toolbar.locator('button').count()==3
   assert page.locator('#resource-operation').evaluate('(e)=>e.previousElementSibling.classList.contains("aws-resource-toolbar")')
   for label in ('AWS 자원 상태 확인','AWS 자원 준비','AWS 자원 삭제'):
    button=toolbar.get_by_role('button',name=label,exact=True);assert button.locator('svg').count()==1;assert button.inner_text()==''
   page.route(f'**/api/resource-status/{mission}',lambda route,request,m=mission:route.fulfill(content_type='application/json',body=json.dumps({'practice_id':m,'read_only':True,'state':'absent','checked_at':'2026-10-10T00:00:00Z','resources':[{'type':'Knowledge Base','name':'fixture-kb','state':'absent'}]})))
   toolbar.get_by_role('button',name='AWS 자원 상태 확인').click()
   group=toolbar.locator('..');expect(group).to_contain_text('Knowledge Base: 미생성');assert not group.get_by_text('RAW 응답 전체',exact=True).locator('..').evaluate('e=>e.open')
   assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 print('PASS: three accessible SVG controls grouped, status read-only display and closed RAW, all three missions desktop/mobile')
 b.close()
