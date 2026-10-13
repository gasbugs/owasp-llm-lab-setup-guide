from playwright.sync_api import sync_playwright
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle')
 ids=['raw','tutorial-result','resource-raw','mission-experience-raw','h23-chat-raw','model-connection-raw']
 for item in ids:
  assert page.evaluate('(id)=>document.getElementById(id).closest("details").open',item) is False,item
  page.evaluate('(id)=>{document.getElementById(id).closest("details").open=true;setText(id,"fixture raw response");}',item)
  assert page.evaluate('(id)=>document.getElementById(id).closest("details").open',item) is False,item
 page.evaluate('selectTab(1,"P23")');page.locator('#h23-grade-tab').click();page.evaluate('renderEnvelope({activity_id:"P23",course_verdict:"ERR",task_completed:false,result:{}})')
 page.locator('details.raw:has(#raw) summary').click();assert page.evaluate('document.getElementById("raw").closest("details").open') is True
 print('PASS: six RAW disclosures default closed, collapse on fresh/restored response, user can expand full result')
 b.close()
