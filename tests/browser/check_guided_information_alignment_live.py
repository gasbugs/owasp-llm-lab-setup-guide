from playwright.sync_api import sync_playwright
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto('http://127.0.0.1:28097',wait_until='networkidle');failures=[];count=0
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':1000})
  for mission in page.evaluate('missionOrder'):
   page.evaluate('(id)=>{if(id==="P00")selectWorkspace("tutorial");else selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);}',mission)
   for pane in ('experience','grade'):
    page.evaluate('({id,pane})=>{if(id==="P00")selectTutorialPane(pane);else if(id==="P01")selectP01Pane(pane==="grade"?"grade":"model");else selectModelCallPane(pane);}',{'id':mission,'pane':pane})
    notes=page.locator('.action-tooltip:visible,.action-tip:visible').evaluate_all('els=>els.map(e=>{const parent=e.closest(".action-control")||e.parentElement;const ps=getComputedStyle(parent),r=parent.getBoundingClientRect(),n=e.getBoundingClientRect();return {id:e.id,width:n.width,target:r.width-parseFloat(ps.paddingLeft)-parseFloat(ps.paddingRight)-parseFloat(ps.borderLeftWidth)-parseFloat(ps.borderRightWidth)}})')
    count+=len(notes)
    failures.extend((width,mission,pane,n) for n in notes if abs(n['width']-n['target'])>2)
    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),(width,mission,pane)
 assert not failures,failures
 print(f'PASS: {count} visible information blocks match container width across P00–P23, both panes, desktop/mobile')
 b.close()
