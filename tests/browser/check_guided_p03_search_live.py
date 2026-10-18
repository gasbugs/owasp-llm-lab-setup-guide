"""Direct search UI contract fixtures; no live AWS or grading."""
import json
from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page(viewport={'width':1440,'height':1000});errors=[];requests=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 page.evaluate('selectTab(1,"P03"); selectModelCallPane("experience")')
 expect(page.locator('#knowledge-search-form')).to_be_visible()
 expect(page.locator('#knowledge-search-submit')).to_be_disabled()
 expect(page.locator('#aws-console-links [aria-disabled="true"]')).to_have_count(6)
 types=['S3 source bucket','S3 vector bucket','Vector index','IAM role','Knowledge Base','Data source']
 resources=[{'type':kind,'name':f'fixture-{i}','state':'present','console_url':f'https://us-east-1.console.aws.amazon.com/bedrock/home?resource={i}'} for i,kind in enumerate(types)]
 status=[{'state':'present','search_ready':True,'checked_at':'2026-10-10T00:00:00Z','resources':resources}]
 page.route('**/api/resource-status/P03',lambda route:route.fulfill(json=status[0]))
 page.evaluate('renderEnvelope({activity_id:"P03",resource_ready:true})')
 expect(page.locator('#aws-console-links a')).to_have_count(6)
 expect(page.locator('#knowledge-search-submit')).to_be_enabled()
 assert page.locator('#aws-console-links a').first.get_attribute('target')=='_blank'
 status[0]={'state':'absent','search_ready':False,'checked_at':'2026-10-10T00:01:00Z','resources':[]}
 page.evaluate('renderEnvelope({activity_id:"P03",resource_deleted:true})')
 expect(page.locator('#aws-console-links a')).to_have_count(0)
 expect(page.locator('#knowledge-search-submit')).to_be_disabled()
 expect(page.locator('#aws-console-links [aria-disabled="true"]')).to_have_count(6)
 page.evaluate('updateKnowledgeLinks({resources:[{type:"Knowledge Base",state:"present",name:"invalid",console_url:"https://example.com/"}]})')
 expect(page.locator('#aws-console-links a')).to_have_count(0)

 expect(page.locator('#mission-experience-run')).to_be_hidden()
 expect(page.locator('#h03-work')).to_contain_text('~/owasp-llm-practice/P01-03_learner.py')
 page.evaluate('updateKnowledgeLinks({state:"present", search_ready:false, resources:[]})')
 expect(page.locator('#knowledge-search-submit')).to_be_disabled()
 page.evaluate('updateKnowledgeLinks({state:"present", search_ready:true, resources:[]})')
 expect(page.locator('#knowledge-search-submit')).to_be_enabled()
 page.evaluate('selectTab(2,"P04"); selectModelCallPane("experience")')
 expect(page.locator('#aws-console-links [aria-disabled="true"]')).to_have_count(1)
 page.evaluate('updateGuardrailChat({state:"present",model_ready:true,resources:[{type:"AWS Guardrail",state:"present",name:"fixture-guardrail",console_url:"https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/guardrails"}]})')
 expect(page.locator('#aws-console-links a')).to_have_count(1)
 expect(page.locator('#knowledge-search-form')).to_be_hidden()
 expect(page.locator('#document-upload-form')).to_be_hidden()
 expect(page.locator('#mission-experience-run')).to_be_hidden()
 expect(page.locator('#mission-experience-run').locator('xpath=following-sibling::*[1]')).to_be_hidden()
 page.evaluate('selectTab(1,"P03"); selectModelCallPane("experience")')
 expect(page.locator('#knowledge-search-form')).to_be_visible()
 replies=[{'status':'ready','result':{'results':[{'content':{'text':'계정 접근 절차 <script>unsafe()</script>'},'location':{'s3Location':{'uri':'s3://fixture/knowledge/current.md'}},'score':.82}]}}, {'status':'ready','result':{'results':[]}}, {'status':'waiting','result':None}]
 def search(route):
  body=route.request.post_data_json;requests.append(body)
  route.fulfill(json={'practice_id':'P03','graded':False,'query':body['query'],'execution':{'lifecycle_status':'finished','execution':{'execution_status':'returned','result':replies.pop(0)}}})
 page.route('**/api/knowledge/search',search)
 page.route('**/api/practice/P03/verify',lambda route: (_ for _ in ()).throw(AssertionError('direct search attempted grading')))
 page.locator('#knowledge-search-query').fill('계정 접근 절차')
 page.locator('#knowledge-search-submit').click()
 expect(page.locator('#mission-experience-status')).to_have_text('검색 결과 1건을 찾았습니다.')
 expect(page.locator('#mission-experience-summary')).to_contain_text('계정 접근 절차 <script>unsafe()</script>')
 expect(page.locator('#mission-experience-summary')).to_contain_text('s3://fixture/knowledge/current.md')
 expect(page.locator('#mission-experience-summary')).to_contain_text('0.82')
 assert page.locator('#mission-experience-summary script').count()==0
 assert not page.locator('#mission-experience-details').evaluate('(el)=>el.open')
 page.locator('#knowledge-search-query').fill('없는 내용 검색')
 page.locator('#knowledge-search-submit').click()
 expect(page.locator('#mission-experience-status')).to_have_text('검색 결과 0건을 찾았습니다.')
 expect(page.locator('#mission-experience-summary .case-card')).to_have_count(0)
 page.locator('#knowledge-search-submit').click()
 expect(page.locator('#mission-experience-status')).to_contain_text('문서 동기화가 진행 중')
 assert requests[0]=={'query':'계정 접근 절차'}
 for width in [1440,390]:
  page.set_viewport_size({'width':width,'height':1000})
  assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),width
 assert not errors,errors
 print('PASS: P03 query form, correct query request, text/source/score, safe text rendering, 0 hits and pending state, RAW collapsed, responsive; no grading/AWS calls')
 b.close()
