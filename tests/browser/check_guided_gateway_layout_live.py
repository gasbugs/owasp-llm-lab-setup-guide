"""Gateway uses the common mission columns and separate direct/grading panes."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page(viewport={'width':1440,'height':1000});errors=[]
 page.on('pageerror',lambda error:errors.append(str(error)))
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('selectTab(0,"P01")')
 expect(page.locator('#mission-guidance #h01-work')).to_be_visible()
 expect(page.locator('#mission-execution #gateway-execution')).to_be_visible()
 expect(page.locator('#chat-form')).to_be_visible()
 expect(page.locator('#verify')).to_be_hidden()
 left=page.locator('#mission-guidance').bounding_box();right=page.locator('#mission-execution').bounding_box()
 assert abs(left['y']-right['y'])<2
 assert left['x']+left['width'] <= right['x']+1
 statement=page.locator('#h01-work .p01-statement').bounding_box()
 assert abs(statement['x']-left['x']-20)<2
 assert page.locator('#h01-work .mission-context').evaluate('(el)=>el.parentElement.classList.contains("p01-statement")')
 page.locator('#p01-grade-tab').click()
 expect(page.locator('#verify')).to_be_visible();expect(page.locator('#chat-form')).to_be_hidden()
 expect(page.locator('#verify')).to_have_text('미션 채점')
 page.evaluate('selectTab(2,"P04")')
 expect(page.locator('#gateway-execution')).to_be_hidden()
 expect(page.locator('#guardrail-chat-form')).to_be_visible()
 other=page.locator('#mission-execution').bounding_box()
 assert abs(other['x']-right['x'])<2 and abs(other['y']-right['y'])<2
 page.evaluate('selectTab(0,"P01")')
 expect(page.locator('#chat-form')).to_be_visible()
 for width in [1000,390]:
  page.set_viewport_size({'width':width,'height':1000})
  left=page.locator('#mission-guidance').bounding_box();right=page.locator('#mission-execution').bounding_box()
  assert right['y'] >= left['y']+left['height']-1
  assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),width
 assert not errors,errors
 print('PASS: shared columns/top alignment/padding, separate model/grading, cross-mission isolation, 1000/390px responsive; no model calls')
 b.close()
