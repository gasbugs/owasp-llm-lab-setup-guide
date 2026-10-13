"""Verify one selected mission per page without running a backend job."""
import json
import sys
from playwright.sync_api import sync_playwright, expect

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors, posts = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    def block_post(route):
        if route.request.method == "POST":
            posts.append(route.request.url)
            route.abort()
        else:
            route.continue_()
    page.route("**/api/**", block_post)
    page.goto("http://127.0.0.1:28097", wait_until="networkidle")
    assert page.locator('#tabs .tab').count() == 24
    assert page.locator('.mission-category').count() == 7
    assert page.locator('.mission-category[data-category="04"] .tab').count() == 8
    assert page.locator('.mission-category').evaluate_all('els => els.map(el => el.dataset.category)') == ['01', '02', '03', '04', '05', '06', '07']
    assert page.locator('#p00-menu > span').inner_text() in ['P00', '🎉']
    page.evaluate('setMissionMenu(true)')
    category = page.locator('.mission-category[data-category="01"]')
    category.locator('summary').click()
    assert category.evaluate('el => el.open')
    assert category.locator('.category-number').evaluate('el => getComputedStyle(el).color') != category.locator('.tab > span').first.evaluate('el => getComputedStyle(el).color')
    category.locator('summary').click()
    assert not category.evaluate('el => el.open')
    category.locator('summary').focus()
    page.keyboard.press('Enter')
    assert category.evaluate('el => el.open')
    page.keyboard.press('Enter')
    assert not category.evaluate('el => el.open')
    if len(sys.argv) > 1:
        page.screenshot(path=sys.argv[1])
    for width in [1440, 390]:
        page.set_viewport_size({"width": width, "height": 1000})
        tops = []
        for problem in page.evaluate('missionOrder.filter(id => id !== "P00")'):
            page.evaluate('setMissionMenu(true)')
            item = page.locator(f'#tabs .tab[data-problem="{problem}"]')
            item.evaluate('el => el.closest("details").open = true')
            item.click()
            visible = page.locator('.lab-workspace:visible')
            tops.append(page.locator("#practice-workbench .work-body").bounding_box()["y"])
            assert visible.count() == 1
            title = page.locator("#activity-title").inner_text()
            assert title not in visible.locator("h3:visible").all_text_contents()
            assert page.evaluate('window.scrollY') == 0
            assert page.locator('#breadcrumb-current').inner_text().startswith(page.evaluate('id => missionLabel(id)', problem))
            assert visible.get_attribute('id') == 'h' + problem[1:] + '-work'
            expect(page.locator('#current-station')).to_have_text(page.evaluate('id => missionLabel(id)', problem))
            if problem != 'P01':
                page.locator('#h23-grade-tab').click()
                actions = page.locator('#mission-execution-actions > section:visible')
                assert actions.count() == 1
                assert actions.get_attribute('data-problem') == problem
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert max(tops) - min(tops) < 1, tops
    page.evaluate('selectTab(1, "P02")')
    page.evaluate('''() => {
        const payload = {activity_id: "P02", result: {cases: []}, stage_calls: []};
        missionResults.set("P02", payload); renderEnvelope(payload);
    }''')
    expect(page.locator('#raw')).to_contain_text('P02')
    page.evaluate('selectTab(1, "P03")')
    expect(page.locator('#raw')).to_be_hidden()
    page.evaluate('selectTab(1, "P02")')
    page.locator('#h23-grade-tab').click()
    assert not page.locator('#raw').locator('..').get_attribute('open')
    page.locator('#raw').locator('..').locator('summary').click()
    expect(page.locator('#raw')).to_be_visible()
    expect(page.locator('#raw')).to_contain_text('P02')
    page.set_viewport_size({"width": 1440, "height": 2400})
    page.evaluate('setMissionMenu(true)')
    for problem in ["P02", "P01", "P04", "P22"]:
        page.evaluate('id => selectTab(practiceGroups.findIndex(group => group.includes(id)), id)', problem)
        assert page.locator('.workspace-shell > .app').bounding_box()["y"] == 0
        assert page.locator('.workspace-shell > .app').evaluate('el => getComputedStyle(el).marginTop') == '0px'
    page.evaluate('celebratePractice("P00"); celebratePractice("P00")')
    assert page.locator('.completion-burst').count() == 2
    assert page.locator('.completion-burst i').count() == 320
    page.evaluate('dismissCelebration()')
    assert not posts and not errors, (posts, errors)
    print(json.dumps({"individual_menu_entries": 24, "single_mission_views": 46,
                      "result_isolation": True, "backend_posts": 0, "errors": errors}))
    browser.close()
