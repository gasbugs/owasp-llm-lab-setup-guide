"""Restore sanitized recorded responses for every mission; display only, no grading."""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ORIGIN = os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097")
REPORTS = Path(os.getenv("GUIDED_UI_REPORTS_DIR", str(Path(__file__).resolve().parents[1] / "fixtures/guided-ui-reports")))

with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context()
    page = context.new_page()
    errors, mutations = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda request: mutations.append(request.url) if request.method == "POST" else None)
    page.goto(ORIGIN, wait_until="networkidle")
    missions = page.evaluate("missionOrder")
    records = json.loads((REPORTS / "manifest.json").read_text())["records"]
    assert {record["mission"] for record in records} == set(missions)
    before = page.evaluate('fetch("/api/progress").then(r=>r.json())')

    def select(mission):
        page.evaluate('id=>{if(id==="P00"){selectWorkspace("tutorial");selectTutorialPane("grade");}'
                      'else{selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);'
                      'if(id==="P01")selectP01Pane("grade");else selectModelCallPane("grade");}}', mission)

    count = 0
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 1000})
        for record in records:
            mission = record["mission"]
            original_raw = (REPORTS / record["file"]).read_text()
            select(mission)
            page.evaluate('({id,raw})=>{const payload=JSON.parse(raw);rawResponses.set(payload,formatRawJson(raw));'
                          'payload.access_token="must-not-be-cached";cacheGradingResult(id,payload,Date.now()-1250);'
                          'const saved=JSON.parse(sessionStorage.getItem(`guided-grading-result-${id}`));'
                          'restoreGradingRaw(saved);if(id==="P00")displayTutorialGrade(saved);else renderEnvelope(saved);}',
                          {"id": mission, "raw": original_raw})
            cache = page.evaluate('id=>sessionStorage.getItem(`guided-grading-result-${id}`)', mission)
            assert "must-not-be-cached" not in cache
            container = "#tutorial-cases" if mission == "P00" else "#case-results-list"
            cards = page.locator(container + " > .case-card")
            expect(cards).to_have_count(record["case_count"])
            expect(page.locator("#case-progress")).to_be_hidden()
            labels = cards.locator(".case-badge").all_text_contents()
            titles = cards.locator(".case-card-heading > strong").all_text_contents()
            clock = "#tutorial-checked-at" if mission == "P00" else "#grading-checked-at"
            timestamp = page.locator(clock).inner_text()
            assert "소요 1.3초" in timestamp, timestamp
            raw_before = page.locator("#tutorial-result" if mission == "P00" else "#raw").text_content()
            if mission != "P00":
                assert raw_before == page.evaluate("raw=>formatRawJson(raw)", original_raw)
            assert not page.locator(container + " details[open]").count()
            details = page.locator(container + " details")
            if details.count():
                details.first.locator("summary").focus()
                page.keyboard.press("Enter")
                assert details.first.get_attribute("open") is not None
            page.reload(wait_until="networkidle")
            if mission == "P00":
                expect(page.locator("#tutorial-grade-panel")).to_be_visible()
            else:
                assert page.evaluate("activeProblem") == mission
                grade = "#p01-grade-panel" if mission == "P01" else "#h23-grade-tab"
                expect(page.locator(grade)).to_be_visible()
                if mission != "P01":
                    assert page.locator(grade).get_attribute("aria-selected") == "true"
            expect(cards).to_have_count(record["case_count"])
            expect(page.locator("#case-progress")).to_be_hidden()
            assert cards.locator(".case-badge").all_text_contents() == labels
            assert cards.locator(".case-card-heading > strong").all_text_contents() == titles
            assert page.locator(clock).inner_text() == timestamp
            assert not page.locator(container + " details[open]").count()
            raw = "#tutorial-result" if mission == "P00" else "#raw"
            assert page.locator(raw).text_content() == raw_before
            assert page.locator(raw).locator("xpath=ancestor::details[1]").get_attribute("open") is None
            assert not page.locator("#completion-confetti .completion-burst").count()
            expect(page.locator("#completion-toast")).to_be_hidden()
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (mission, width)
            other = "P23" if mission == "P00" else "P00"
            select(other)
            select(mission)
            assert cards.locator(".case-badge").all_text_contents() == labels
            count += 1
    sibling = context.new_page()
    sibling.goto(ORIGIN, wait_until="networkidle")
    assert not sibling.evaluate('missionOrder.some(id=>sessionStorage.getItem(`guided-grading-result-${id}`))')
    assert before == page.evaluate('fetch("/api/progress").then(r=>r.json())')
    assert not errors and not mutations, (errors, mutations)
    print(f"PASS: all {len(missions)} missions, {count} recorded/explicit-contract response views/reloads; exact badges/time, closed details/RAW, isolated tabs, no grade/completion writes")
    browser.close()
