from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page(viewport={'width':1100,'height':850});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('completedPractices.clear();completedPractices.set("P01",{});completedPractices.set("P23",{});p00Completed=true;renderPracticeProgress();selectWorkspace("home")')
 expect(page.locator('#home-completed-value')).to_have_text('3');expect(page.locator('#home-total')).to_have_text('24');expect(page.locator('#home-percent')).to_have_text('13%');expect(page.locator('#home-remaining')).to_have_text('21');assert page.locator('.home-mission.is-complete').count()==3
 for width in (1100,1440,390):
  page.set_viewport_size({'width':width,'height':850});page.evaluate('selectWorkspace("tutorial")')
  left=page.locator('#tutorial-panel .p01-statement').bounding_box();right=page.locator('.tutorial-execution').bounding_box()
  if width>1000: assert abs(left['y']-right['y'])<2 and right['x']>=left['x']+left['width']-2,(width,left,right)
  else: assert right['y']>=left['y']+left['height']-2,(width,left,right)
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),width
 assert not errors,errors
 print('PASS: 3 completed cards = 3/24, 13%, remaining21; P00 side-by-side1100/1440; mobile390 stacked without overflow')
 b.close()
