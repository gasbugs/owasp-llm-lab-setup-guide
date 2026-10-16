"""Actual menu transitions and pane restoration; no learner/provider writes."""
import os
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
 b=p.chromium.launch(); page=b.new_page(); errors=[]; mutations=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.on('request',lambda r:mutations.append(r.url) if r.method=='POST' and '/session' not in r.url else None)
 page.goto(os.getenv('GUIDED_UI_BASE_URL','http://127.0.0.1:28097'),wait_until='networkidle')
 ids=page.evaluate('missionOrder'); assert len(ids)==24,ids
 before=page.evaluate('fetch("/api/progress").then(r=>r.json())')
 def select(mid):
  page.evaluate('setMissionMenu(true);document.querySelectorAll(".mission-category").forEach(e=>e.open=true)')
  page.locator('#p00-menu' if mid=='P00' else f'.tab[data-problem="{mid}"]').click()
  if mid=='P00': expect(page.locator('#tutorial-panel')).to_be_visible()
  else:
   assert page.evaluate('activeProblem')==mid
   expect(page.locator('#mission-guidance')).to_be_visible()
   expect(page.locator('#mission-execution')).to_be_visible()
   visible=page.locator('.lab-workspace:visible')
   assert visible.count()==1 and visible.get_attribute('id')=='h'+mid[1:]+'-work',mid
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),mid
 page.set_viewport_size({'width':390,'height':700})
 page.evaluate('selectTab(1,"P02");window.scrollTo(0,800)')
 assert page.evaluate('scrollY')>0
 select('P00')
 assert page.evaluate('scrollY')==0
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':900})
  for source in ids:
   select(source)
   for target in ids: select(target)
  for mid in ids:
   select(mid)
   if mid=='P00': page.locator('#tutorial-grade-tab').click()
   elif mid=='P01': page.locator('#p01-grade-tab').click()
   else: page.locator('#h23-grade-tab').click()
   page.reload(wait_until='networkidle')
   if mid=='P00': expect(page.locator('#tutorial-grade-panel')).to_be_visible()
   elif mid=='P01': expect(page.locator('#p01-grade-panel')).to_be_visible()
   else:
    page.wait_for_function('(expected) => activeProblem === expected', arg=mid, timeout=10000)
    assert page.locator('#h23-grade-tab').get_attribute('aria-selected')=='true'
   assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),mid
  print(f'PASS width={width}: 576 menu transitions + 24 grade-pane reloads',flush=True)
 assert before==page.evaluate('fetch("/api/progress").then(r=>r.json())')
 assert not errors and not mutations,(errors,mutations)
 b.close()
