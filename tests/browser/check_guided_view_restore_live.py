from playwright.sync_api import sync_playwright,expect
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle');mutations=[]
 page.on('request',lambda req:mutations.append(req.url) if req.method=='POST' else None)
 for mission,pane in [('P02','experience'),('P23','grade'),('P01','grade'),('P00','grade')]:
  page.evaluate('({mission,pane})=>{if(mission==="P00"){selectWorkspace("tutorial");selectTutorialPane(pane);}else{selectTab(practiceGroups.findIndex(g=>g.includes(mission)),mission);if(mission==="P01")selectP01Pane(pane==="grade"?"grade":"model");else selectModelCallPane(pane);}}',{'mission':mission,'pane':pane})
  page.reload(wait_until='networkidle')
  if mission=='P00':expect(page.locator('#tutorial-grade-panel')).to_be_visible()
  else:
   assert page.evaluate('activeProblem')==mission
   if mission=='P01':expect(page.locator('#p01-grade-panel')).to_be_visible()
   else:assert page.locator('#h23-'+('grade' if pane=='grade' else 'experience')+'-tab').get_attribute('aria-selected')=='true'
 page.evaluate('selectWorkspace("home")');page.reload(wait_until='networkidle');expect(page.locator('#home-panel')).to_be_visible()
 assert not mutations,mutations
 page.evaluate('selectTab(1,"P02");selectModelCallPane("experience");updateDocumentLinks({state:"absent",resources:[]});')
 for kind in ('s3','titan'):
  wrapper=page.locator('#document-'+kind+'-link').locator('..');wrapper.hover();expect(wrapper.locator('[role="tooltip"]')).to_be_visible();expect(wrapper.locator('[role="tooltip"]')).to_have_text('자원 상태를 먼저 확인하세요')
  wrapper.focus();expect(wrapper.locator('[role="tooltip"]')).to_be_visible()
 print('PASS: refresh restores home/P00/mission and tab without POST; disabled AWS links explain state check on hover/focus')
 b.close()
