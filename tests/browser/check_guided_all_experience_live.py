"""Native direct-test UI fixtures, distinct from actual product or AWS validation."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
    browser=p.chromium.launch();page=browser.new_page(viewport={"width":1440,"height":1000})
    errors=[];requests=[]
    page.on("pageerror",lambda error:errors.append(str(error)))
    page.goto("http://127.0.0.1:28097",wait_until="networkidle")
    catalog=page.evaluate('fetch("/api/experience-catalog").then(r=>r.json())')
    before=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    def native(route):
        requests.append(route.request.post_data_json)
        route.fulfill(json={"graded":False,"result":{"reply":"기능 응답 표시", "details":{"decision":"allow"}}})
    page.route("**/api/experience/*",native)
    page.route("**/api/practice/*/verify",lambda route:(_ for _ in ()).throw(AssertionError("Direct test called grading")))
    for width in (1440,390):
        page.set_viewport_size({"width":width,"height":1000})
        for problem,config in catalog.items():
            page.evaluate('(id)=>{selectTab(practiceGroups.findIndex(group=>group.includes(id)),id);selectModelCallPane("experience");}',problem)
            expect(page.locator("#mission-experience-run")).to_be_visible()
            if config["mode"] in ("message","operation"):
                page.locator("#native-message").fill("새로운 문장입니다.")
                page.locator("#h23-grade-tab").click();page.locator("#h23-experience-tab").click()
                expect(page.locator("#native-message")).to_have_value("새로운 문장입니다.")
            elif config["mode"]=="scenario":
                expect(page.locator("#native-scenario")).to_be_visible()
                assert bool(page.locator("#native-message").get_attribute("readonly") is not None)==(not config.get("editable",False))
            page.locator("#mission-experience-run").click()
            expect(page.locator("#mission-experience-summary")).to_contain_text("기능 응답 표시")
            assert not page.locator("#mission-experience-summary details").get_attribute("open")
            if width==1440:
                left=page.locator("#mission-guidance").bounding_box();right=page.locator("#mission-execution").bounding_box()
                assert right["x"]>left["x"] and abs(right["y"]-left["y"])<2,(problem,left,right)
            page.locator("#h23-grade-tab").click()
            expect(page.locator(f"#h{problem[1:]}-verify")).to_be_visible()
            expect(page.locator("#mission-experience")).to_be_hidden()
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),problem
    page.set_viewport_size({"width":1440,"height":1000})
    for problem,other in (("P07","P08"),("P11","P05"),("P09","P06")):
        page.evaluate('(id)=>{selectTab(practiceGroups.findIndex(group=>group.includes(id)),id);selectModelCallPane("experience");}',problem)
        page.locator("#native-message").fill("미션별로 보존할 입력 "+problem)
        page.evaluate('(id)=>{selectTab(practiceGroups.findIndex(group=>group.includes(id)),id);selectModelCallPane("experience");}',other)
        page.evaluate('(id)=>{selectTab(practiceGroups.findIndex(group=>group.includes(id)),id);selectModelCallPane("experience");}',problem)
        expect(page.locator("#native-message")).to_have_value("미션별로 보존할 입력 "+problem)
    after=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    assert before==after and len(requests)==36 and not errors,(len(requests),errors)
    print("PASS: 18 missions × 2 widths; native inputs, answer cards, collapsed detail, unchanged completion")
    browser.close()
