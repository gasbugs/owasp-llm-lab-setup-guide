from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();errors=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 assert page.locator('.mission-category[open]').count()==0
 page.evaluate('setMissionMenu(true)')
 for category in ['01','04']:
  page.locator(f'.mission-category[data-category="{category}"] summary').click()
 page.wait_for_function('localStorage.getItem("guided-category-open-01")==="true" && localStorage.getItem("guided-category-open-04")==="true"')
 page.reload(wait_until='networkidle')
 page.evaluate('setMissionMenu(true)')
 assert page.locator('.mission-category[open]').evaluate_all('els=>els.map(el=>el.dataset.category)')==['01','04']
 page.locator('.mission-category[data-category="01"] summary').click()
 page.wait_for_function('localStorage.getItem("guided-category-open-01")==="false"')
 page.evaluate('selectTab(0,"P01")')
 assert not page.locator('.mission-category[data-category="03"]').evaluate('el=>el.open')
 page.reload(wait_until='networkidle')
 page.evaluate('setMissionMenu(true)')
 assert page.locator('.mission-category[open]').evaluate_all('els=>els.map(el=>el.dataset.category)')==['04']
 assert not errors,errors
 print('PASS: first visit closed; independent open/closed states survive reload; mission selection does not reopen closed categories')
 b.close()
