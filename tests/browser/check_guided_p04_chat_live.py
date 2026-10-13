"""P04 direct UI fixtures: custom question, real-response rendering, no grading."""
from playwright.sync_api import sync_playwright, expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page(viewport={"width":1440,"height":1000});errors=[];calls=[]
 page.on("pageerror",lambda error:errors.append(str(error)))
 page.goto("http://127.0.0.1:28097",wait_until="networkidle")
 page.evaluate('selectTab(2,"P04"); selectModelCallPane("experience")')
 expect(page.locator("#guardrail-chat-form")).to_be_visible()
 expect(page.locator("#knowledge-search-form")).to_be_hidden()
 expect(page.locator("#guardrail-chat-submit")).to_be_disabled()
 page.route("**/api/resource-status/P04",lambda route:route.fulfill(json={"practice_id":"P04","state":"present","model_ready":True,"checked_at":"2026-10-10T09:00:00Z","resources":[]}))
 page.locator('[data-resource-status="P04"]').click()
 expect(page.locator("#guardrail-chat-submit")).to_be_enabled()
 def chat(route):
  calls.append(route.request.post_data_json)
  route.fulfill(json={"practice_id":"P04","graded":False,"message":calls[-1]["message"],"execution":{"lifecycle_status":"finished","execution":{"execution_status":"returned","result":{"output":{"message":{"content":[{"text":"담당자 이메일은 {EMAIL} 입니다."}]}},"stopReason":"guardrail_intervened","usage":{"inputTokens":30,"outputTokens":12},"trace":{"guardrail":{"outputAssessments":{"fixture":[]}}}}}}})
 page.route("**/api/practice/P04/chat",chat)
 page.route("**/api/practice/P04/verify",lambda route:(_ for _ in ()).throw(AssertionError("direct chat attempted grading")))
 page.locator("#guardrail-chat-message").fill("담당자 이메일은 learner@example.com 입니다.")
 page.locator("#guardrail-chat-submit").click()
 expect(page.locator("#mission-experience-status")).to_have_text("정책이 적용된 모델 응답을 받았습니다.")
 expect(page.locator("#mission-experience-summary")).to_contain_text("{EMAIL}")
 expect(page.locator("#mission-experience-summary")).to_contain_text("guardrail_intervened")
 expect(page.locator("#mission-experience-summary summary")).to_have_text("Guardrail 정책 적용 내역")
 assert calls==[{"message":"담당자 이메일은 learner@example.com 입니다."}]
 page.locator("#h23-grade-tab").click();expect(page.locator("#h04-verify")).to_be_visible()
 expect(page.locator("#guardrail-chat-form")).to_be_hidden()
 assert not errors,errors
 print("PASS: custom prompt, guarded reply/trace, readiness lock, separate grading; fixtures only")
 b.close()
