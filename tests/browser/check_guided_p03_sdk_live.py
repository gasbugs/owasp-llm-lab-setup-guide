"""P01-03 SDK problem surface; no provisioning, grading or AWS requests."""
import json
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser=p.chromium.launch()
    page=browser.new_page(viewport={'width':1440,'height':1000})
    errors=[];posts=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    def route(request):
        if request.request.method=='POST':posts.append(request.request.url);request.abort()
        else:request.continue_()
    page.route('**/api/**',route)
    page.goto('http://127.0.0.1:28097',wait_until='networkidle')
    page.evaluate('selectTab(1,"P03")')
    text=page.locator('#h03-work').inner_text()
    for word in ('load_aws_session','bedrock-agent','get_ingestion_job','runtime.retrieve','binding','15분'):
        assert word in text,word
    assert 'services.job_status' not in text and 'services.retrieve' not in text
    for width in (1440,390):
        page.set_viewport_size({'width':width,'height':1000})
        assert page.locator('.lab-workspace:visible').count()==1
        assert page.locator('#h03-work').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert page.locator('#h03-work').bounding_box()['y']>=0
    assert errors==[],errors
    assert posts==[],posts
    print(json.dumps({'sdk_problem_surface':'PASS','viewports':[1440,390],'page_errors':errors,'automatic_posts':posts}))
    browser.close()
