"""Mission navigation retains menu scroll while resetting the lesson body."""
from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
    browser=p.chromium.launch();page=browser.new_page(viewport={"width":1440,"height":720})
    page.goto("http://127.0.0.1:28097",wait_until="networkidle")
    page.evaluate('setSidebarPinned(true);setMissionMenu(true);document.querySelectorAll(".mission-category").forEach(el=>el.open=true)')
    menu=page.locator("#mission-menu")
    item=page.locator('.tab[data-problem="P21"]')
    item.scroll_into_view_if_needed()
    before=menu.evaluate('el=>el.scrollTop')
    assert before>100,before
    item.click();page.wait_for_timeout(200)
    after=menu.evaluate('el=>el.scrollTop')
    assert abs(after-before)<2,(before,after)
    assert page.evaluate('activeProblem')=="P21"
    assert page.evaluate('scrollY')==0
    assert menu.evaluate('el=>el.contains(document.activeElement)')
    page.locator('.tab[data-problem="P22"]').focus()
    before=menu.evaluate('el=>el.scrollTop')
    page.keyboard.press("Enter");page.wait_for_timeout(200)
    assert abs(menu.evaluate('el=>el.scrollTop')-before)<2
    assert page.evaluate('activeProblem')=="P22"
    before=menu.evaluate('el=>el.scrollTop')
    page.evaluate('setMissionMenu(false);setMissionMenu(true)')
    assert abs(menu.evaluate('el=>el.scrollTop')-before)<2
    print("PASS: mouse/keyboard mission selection and menu reopening preserve sidebar scroll; lesson starts at top")
    browser.close()
