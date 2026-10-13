"""All P00-P23 recorded case details; UI display only, no fresh provider execution."""
import json,os
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
reports=Path(__file__).resolve().parents[1]/'fixtures/guided-ui-reports'
with sync_playwright() as p:
    browser=p.chromium.launch();page=browser.new_page();errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.goto(os.getenv('GUIDED_UI_BASE_URL','http://127.0.0.1:28097'),wait_until='networkidle')
    before=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    assert len(page.evaluate('Object.keys(caseCatalog)'))==24
    catalog=page.evaluate('caseCatalog')
    assert all(case.get('summary') for mission in catalog.values() for case in mission['cases'].values())
    page.context.grant_permissions(['clipboard-read','clipboard-write'])
    count=0;seen=set();comparisons=0;copies=0
    for width in (1440,390):
        page.set_viewport_size({'width':width,'height':1000})
        for report in json.loads((reports/'manifest.json').read_text())['records']:
            mission=report['mission'];data=json.loads((reports/report['file']).read_text())
            page.evaluate('([id,data])=>{if(id==="P00"){selectWorkspace("tutorial");selectTutorialPane("grade");displayTutorialGrade(data);}else{selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);if(id==="P01")selectP01Pane("grade");else selectModelCallPane("grade");renderEnvelope(data);}}',[mission,data])
            target='#tutorial-cases' if mission=='P00' else '#case-results-list'
            details=page.locator(target+' details')
            assert details.count()==report['case_count'],(mission,report['file'])
            assert page.locator(target+' details[open]').count()==0
            for index in range(details.count()):
                detail=details.nth(index);detail.locator('summary').click()
                expect(detail).to_contain_text('검사 내용')
                assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth'),(mission,width,index)
                tables=detail.locator('.case-comparison table')
                if tables.count():
                    expect(tables).to_contain_text('기대값');expect(tables).to_contain_text('실제값');comparisons+=1
                buttons=detail.locator('.case-copy-id')
                if buttons.count():
                    button=buttons.first;expected=button.get_attribute('aria-label').split(' ')[1]
                    button.click();expect(button).to_have_text('복사됨')
                    assert page.evaluate('navigator.clipboard.readText()')==expected
                    copies+=1

                detail.locator('summary').click();count+=1
            seen.add(mission)
    # Per-case counts differ from two-case aggregates; requests never award a grade.
    p08=json.loads((reports/'p08-1.json').read_text())
    records=page.evaluate('(payload)=>payload.result.cases.map(item=>caseDisplayContext(item,payload,"P08"))',p08)
    for row in records:
        counts={x['field']:x.get('actual') for x in row['case_comparisons']}
        assert counts['self_check_calls']==1
        assert counts['main_calls']==(0 if row['case_id'].startswith('risk-') else 1)
    assert comparisons and copies
    # Explicit display-only check: never confuse a definition with an observed request.
    result=page.evaluate('()=>{const empty=caseDisplayContext({case_id:"risk-phishing-kit",status:"미실행"},{},"P07");const observed=caseDisplayContext({case_id:"risk-phishing-kit",input:"현재 기록에 있는 입력"},{},"P07");return {empty,observed};}')
    assert 'input' not in result['empty'] and result['empty']['defined_request']
    assert result['observed']['input']=='현재 기록에 있는 입력'
    assert len(seen)==24 and not errors,errors
    assert before==page.evaluate('fetch("/api/progress").then(r=>r.json())')
    print(f'PASS: all {len(seen)} missions, {count} detailed case views, {comparisons} comparison tables, {copies} ID copies; request definitions/actual inputs distinct; desktop/mobile; closed toggles; no completion writes')
    browser.close()
