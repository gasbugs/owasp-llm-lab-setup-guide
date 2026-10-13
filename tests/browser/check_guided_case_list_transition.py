"""One visible case list through progress, final results and late progress replies."""
import os
from playwright.sync_api import sync_playwright, expect

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(os.getenv('GUIDED_UI_BASE_URL', 'http://127.0.0.1:28097'), wait_until='networkidle')
    before = page.evaluate('fetch("/api/progress").then(r=>r.json())')
    for width in (1440, 390):
        page.set_viewport_size({'width': width, 'height': 1000})
        for mission in ('P01', 'P04', 'P05'):
            pending_grade, late_progress = [], []
            calls = []
            def progress(route):
                calls.append(route)
                if len(calls) == 1:
                    route.fulfill(json={'phase': 'idle', 'cases': []})
                elif len(calls) == 2:
                    route.fulfill(json={'suite_id': 'display-only', 'phase': 'running', 'total': 2,
                        'cases': [{'case_id': 'completed', 'status': 'PASS'}],
                        'current_case': {'case_id': 'active', 'status': '실행 중'}})
                else:
                    late_progress.append(route)
            grade_url = f'**/api/practice/{mission}/verify'
            progress_url = f'**/api/test-progress/{mission}'
            page.route(grade_url, lambda route: pending_grade.append(route))
            page.route(progress_url, progress)
            page.evaluate('id=>{selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);'
                          'if(id==="P01")selectP01Pane("grade");else selectModelCallPane("grade");'
                          'void execute(`/api/practice/${id}/verify`);}', mission)
            expect(page.locator('#case-progress .case-running-bar')).to_have_count(1)
            expect(page.locator('#case-results')).to_be_hidden()
            expect(page.get_by_role('heading', name='테스트 케이스', exact=True)).to_have_count(1)
            page.wait_for_timeout(650)
            assert pending_grade and late_progress
            pending_grade.pop().fulfill(json={'activity_id': mission, 'execution_id': 'display-only',
                'course_verdict': 'ERR', 'task_completed': False, 'reason': '표시 검사',
                'result': {'cases': [{'case_id': 'final-case', 'status': 'ERR', 'reason': '최종 근거'}]}})
            expect(page.locator('#case-results-list > .case-card')).to_have_count(1)
            expect(page.locator('#case-progress')).to_be_hidden()
            for route in late_progress:
                route.fulfill(json={'suite_id': 'display-only', 'phase': 'running',
                    'cases': [], 'current_case': {'case_id': 'stale-case', 'status': '실행 중'}})
            page.wait_for_timeout(650)
            expect(page.locator('#case-progress')).to_be_hidden()
            expect(page.locator('#case-results')).to_be_visible()
            expect(page.locator('#case-results-list')).to_contain_text('final-case')
            expect(page.get_by_role('heading', name='테스트 케이스', exact=True)).to_have_count(1)
            assert len(calls) == 3, (mission, len(calls))
            assert page.locator('#case-results details[open]').count() == 0
            page.unroute(grade_url)
            page.unroute(progress_url)
    assert not errors, errors
    assert before == page.evaluate('fetch("/api/progress").then(r=>r.json())')
    print('PASS: P01/P04/P05 × desktop/mobile; one list during/after grading; late progress ignored; no final polling or completion writes')
    browser.close()
