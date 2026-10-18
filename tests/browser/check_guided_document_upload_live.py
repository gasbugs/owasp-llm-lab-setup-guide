from playwright.sync_api import sync_playwright, expect
import json
with sync_playwright() as p:
 b=p.chromium.launch(); page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle');requests=[]
 fixture = {'practice_id':'P02','graded':False,'execution':{'lifecycle_status':'finished','closure':{'state':'closed'},'execution':{'execution_status':'returned','calls':[{'operation':'store_source','state':'complete'},{'operation':'embed','state':'complete'}],'result':{'source':{'key':'fixture-source'},'embedding':{'dimensions':1024}}}}}
 def upload(route,request):
  requests.append(request.post_data_json)
  route.fulfill(content_type='application/json',body=json.dumps(fixture))
 page.route('**/api/documents/upload',upload)

 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':1000});page.evaluate('selectTab(1,"P02");selectModelCallPane("experience");updateDocumentLinks({state:"absent",resources:[]})')
  expect(page.locator('#document-upload-form')).to_be_visible();expect(page.locator('#mission-experience-run')).to_be_hidden()
  expect(page.locator('#aws-console-links [aria-disabled="true"]')).to_have_count(2)
  page.evaluate('updateDocumentLinks({state:"present",resources:[{type:"S3 source bucket",name:"fixture-owned-bucket",state:"present",console_url:"https://us-east-1.console.aws.amazon.com/s3/buckets/fixture-owned-bucket"}]})')
  expect(page.locator('#aws-console-links a')).to_have_count(2)
  assert 'fixture-owned-bucket' in page.locator('#aws-console-links a').first.get_attribute('href')
  page.locator('#document-upload-title').fill('내 문서');page.locator('#document-upload-body').fill('입력한 문서가 서버로 전달되는지 확인합니다.');page.locator('#document-upload-submit').click()
  expect(page.locator('#mission-experience-status')).to_contain_text('문서 처리가 완료되었습니다')
  assert requests[-1]=={'title':'내 문서','body':'입력한 문서가 서버로 전달되는지 확인합니다.'}
  assert not page.locator('#mission-experience-details').evaluate('e=>e.open')
  expect(page.locator('#completion-toast')).to_be_hidden()
  page.evaluate('selectTab(1,"P03");selectModelCallPane("experience")');expect(page.locator('#document-upload-form')).to_be_hidden();expect(page.locator('#mission-experience-run')).to_be_hidden()
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 print('PASS: single entered document upload, separate grading, conditional AWS shortcuts, desktop/mobile and mission switch')
 b.close()
