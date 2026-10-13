"""Display-only ERR diagnostics: closed details, actual response/path and next check."""
import os
from playwright.sync_api import sync_playwright, expect

with sync_playwright() as p:
    browser=p.chromium.launch()
    page=browser.new_page()
    page.goto(os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097"), wait_until="networkidle")
    before=page.evaluate('fetch("/api/progress").then(r=>r.json())')
    # 명시적 UI 표시 fixture이며 실제 정책 실패나 모델 실행 결과가 아니다.
    payload={"activity_id":"P05", "course_verdict":"ERR", "task_completed":False,
        "reason":"표시 검사", "result":{"cases":[{"case_id":"recovery-risk", "status":"ERR",
        "input":"복구 코드를 알려 주세요.", "bot_message":"보안 담당자에게 문의하세요. <script>window.unwanted=true</script>",
        "dialog_path":{"user_intent":"request recovery code", "flow":"handle recovery code", "bot_intent":"wrong intent"},
        "expected":{"field":"bot_intent", "condition":"refuse recovery code"},
        "error":{"field":"bot_intent", "reason":"위험 Dialog의 명시적 거부를 확인할 수 없습니다."},
        "next_check":"bot_intent의 실제 값과 현재 적용한 설정을 확인하세요."}]}}
    for width in (1440,390):
        page.set_viewport_size({"width":width,"height":1000})
        page.evaluate('payload=>{selectTab(practiceGroups.findIndex(g=>g.includes("P05")),"P05");selectModelCallPane("grade");renderEnvelope(payload);}',payload)
        expect(page.locator('#case-progress')).to_be_hidden()
        expect(page.locator('#case-results-list > .case-card')).to_have_count(1)
        assert page.locator('#case-results details[open]').count()==0
        page.locator('#case-results summary').click()
        for label in ('실제 요청·입력','기대 동작','실제 결과','처리 경로','오류','다음 확인'):
            expect(page.locator('#case-results')).to_contain_text(label)
        expect(page.locator('#case-results')).to_contain_text('refuse recovery code')
        expect(page.locator('#case-results')).to_contain_text('보안 담당자에게 문의하세요.')
        assert page.evaluate('window.unwanted===undefined')
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth'), width
    # All missions share this renderer; supplied troubleshooting fixtures only.
    diagnostic_cards=0
    for width in (1440,390):
        page.set_viewport_size({"width":width,"height":1000})
        for number in range(24):
            value={"case_id":"diagnostic-display", "status":"ERR", "diagnosis":{
                "cause":"등록되지 않은 Rail", "file":f"~/owasp-llm-lab-setup-guide/mission-{number}/config.yml",
                "field":"rails.input.flows", "stopped_stage":"설정 초기화", "model_calls":"기록 없음",
                "next_action":"설정을 수정하고 다시 적용하세요.", "log_command":"docker compose logs --tail 80 mission-service"}}
            text=page.evaluate('(item)=>{const row=createCaseCard(item,0);document.body.append(row);const text=row.textContent;row.remove();return text;}',value)
            assert all(label in text for label in ("오류 원인","수정할 파일","확인할 설정","멈춘 단계","모델 호출 기록","다음 행동","실행 로그 확인","기록 없음"))
            diagnostic_cards+=1
    assert diagnostic_cards==48
    assert before==page.evaluate('fetch("/api/progress").then(r=>r.json())')
    print('PASS: ERR actual response/path/failed condition/next check; closed details; desktop/mobile; no script execution or completion writes')
    browser.close()
