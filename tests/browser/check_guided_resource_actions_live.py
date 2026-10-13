"""Resource action UI checks with intercepted POSTs; no real AWS calls."""
import json
import time
from playwright.sync_api import sync_playwright, expect

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    errors, calls = [], []
    page.on('pageerror', lambda e: errors.append(str(e)))
    totals = {'P02': {'prepare': 11, 'delete': 9}, 'P03': {'prepare': 13, 'delete': 9}, 'P04': {'prepare': 6, 'delete': 4}}
    progress_state = {'state': 'idle'}
    def mocked(route):
        req = route.request
        if req.method != 'POST':
            route.continue_(); return
        calls.append(req.url)
        problem, action = req.url.split('/')[-2:]
        flag = 'resource_ready' if action == 'provision' else 'resource_deleted'
        route.fulfill(status=200, content_type='application/json', body=json.dumps({
            'activity_id': problem, 'operation_id': 'mock-operation', flag: True,
            'resource_progress': {'current': totals[problem]['prepare' if action == 'provision' else 'delete'], 'total': totals[problem]['prepare' if action == 'provision' else 'delete'], 'title': '최종 응답 확인', 'description': 'AWS 작업 완료'},
            'task_completed': False, 'next_check': '코드를 적용한 뒤 미션 채점을 실행하세요.'}))
    page.route('**/api/practice/**', mocked)
    page.route('**/api/resource-progress/**', lambda route: route.fulfill(status=200, content_type='application/json', body=json.dumps(progress_state)))
    page.goto('http://127.0.0.1:28097', wait_until='networkidle')
    for problem in ('P02', 'P03', 'P04'):
        number = problem[1:]
        page.evaluate('id => selectTab(practiceGroups.findIndex(group => group.includes(id)), id)', problem)
        expect(page.locator('#h23-experience-tab')).to_have_attribute('aria-selected', 'true')
        expect(page.locator(f'#h{number}-provision')).to_be_visible()
        expect(page.locator(f'#h{number}-delete')).to_be_visible()
        expect(page.locator(f'#h{number}-verify')).to_be_hidden()
        page.locator('#h23-grade-tab').click()
        expect(page.locator(f'#h{number}-provision')).to_be_hidden()
        expect(page.locator(f'#h{number}-delete')).to_be_hidden()
        expect(page.locator(f'#h{number}-verify')).to_be_visible()
        page.locator('#h23-experience-tab').click()
        # Hold this request at the browser boundary to inspect the running UI.
        held = []
        progress_state.clear(); progress_state.update(state="idle")
        page.route(f'**/api/practice/{problem}/provision', lambda route: held.append(route))
        page.locator(f'#h{number}-provision').click()
        expect(page.locator('#resource-operation')).to_be_visible()
        expect(page.locator('#resource-operation-count')).to_have_text(f'0 / {totals[problem]["prepare"]}')
        progress_state.update(state='running', operation_id=problem+'-current-operation', current=3, total=totals[problem]['prepare'], title='S3 원문 저장소 준비', description='문서 원문을 보관할 S3 버킷을 준비합니다.')
        expect(page.locator('#resource-operation-count')).to_have_text(f'3 / {totals[problem]["prepare"]}')
        expect(page.locator('#resource-operation-detail')).to_contain_text('문서 원문')
        expect(page.locator('.receipt')).to_be_hidden()
        expect(page.locator('.inspection')).to_be_hidden()
        deadline = time.monotonic() + 5
        while not held and time.monotonic() < deadline:
            page.wait_for_timeout(50)
        assert held
        held[0].fulfill(status=200, content_type='application/json', body=json.dumps({
            'activity_id': problem, 'resource_ready': True, 'task_completed': False,
            'resource_progress': {'current': totals[problem]['prepare'], 'total': totals[problem]['prepare'], 'title': '최종 응답 확인', 'description': 'AWS 작업 완료'},
            'operation_id': 'mock-preparation', 'next_check': '미션 채점을 실행하세요.'}))
        expect(page.locator('#resource-operation-label')).to_have_text('AWS 자원 준비 완료')
        expect(page.locator('#resource-operation-count')).to_have_text(f'{totals[problem]["prepare"]} / {totals[problem]["prepare"]}')
        expect(page.locator('#resource-operation-bar')).to_have_attribute('value', str(totals[problem]['prepare']))
        expect(page.locator('#resource-operation-detail')).to_contain_text('아직 채점하지 않았습니다')
        expect(page.locator('.receipt')).to_be_hidden()
        expect(page.locator('.inspection')).to_be_hidden()
        page.unroute(f'**/api/practice/{problem}/provision')
        before = len(calls)
        page.once('dialog', lambda dialog: dialog.dismiss())
        page.locator(f'#h{number}-delete').click()
        assert len(calls) == before
        page.once('dialog', lambda dialog: dialog.accept())
        page.locator(f'#h{number}-delete').click()
        expect(page.locator('#resource-operation-label')).to_have_text('AWS 자원 삭제 완료')
        assert calls[-1].endswith(f'/{problem}/delete-resources')
        expect(page.locator('.receipt')).to_be_hidden()
        expect(page.locator('.inspection')).to_be_hidden()
        page.locator('#h23-grade-tab').click()
        expect(page.locator('#resource-operation')).to_be_hidden()
        expect(page.locator('#resource-raw-details')).to_be_hidden()
        page.locator('#h23-experience-tab').click()
        page.evaluate('selectTab(0, "P01")')
        expect(page.locator('#resource-operation')).to_be_hidden()
    assert not errors, errors
    print(json.dumps({'resource_missions': 3, 'progress_checked': True, 'cancel_sends_no_request': True,
                      'preparation_is_not_grade': True, 'deletion_posts_intercepted': len(calls), 'errors': errors}))
    browser.close()
