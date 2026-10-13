"""Every mission's displayed edit path resolves to a real learner file; no edits or grades."""
import os,re
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[2]
prefix='~/owasp-llm-lab-setup-guide/'
with sync_playwright() as p:
 b=p.chromium.launch();page=b.new_page();page.goto(os.getenv('GUIDED_UI_BASE_URL','http://127.0.0.1:28097'),wait_until='networkidle')
 count=0
 for width in (1440,390):
  page.set_viewport_size({'width':width,'height':900})
  for mission in page.evaluate('missionOrder'):
   if mission=='P00':continue
   page.evaluate('(id)=>selectTab(practiceGroups.findIndex(g=>g.includes(id)),id)',mission)
   panel=page.locator('#h'+mission[1:]+'-work')
   paths=panel.locator('code').all_text_contents();paths=[x for x in paths if 'guided-labs/' in x]
   assert paths,mission
   for path in paths:
    assert path.startswith(prefix), (mission,path)
    assert f'/guided-labs/h{mission[1:]}-' in path,(mission,path)
    assert (root/path.removeprefix(prefix)).is_file(),(mission,path)
   for block in panel.locator('pre').all_text_contents():
    if 'docker compose' in block:assert block.lstrip().startswith('cd ~/owasp-llm-lab-setup-guide'),(mission,block)
    for path in re.findall(r'\b(?:vi|cat)\s+(\S*guided-labs/\S+)',block):
     assert path.startswith(prefix),(mission,path)
     assert f'/guided-labs/h{mission[1:]}-' in path,(mission,path)
   gaps=panel.locator('.hands-on > div > :is(p:not(.label), ul, ol, pre, details) + h3').evaluate_all('(headings)=>headings.map(h=>({title:h.textContent,gap:h.getBoundingClientRect().top-h.previousElementSibling.getBoundingClientRect().bottom}))')
   for item in gaps:assert item['gap']>=24,(mission,width,item)
   assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),mission
   count+=1
 print(f'PASS: {count} desktop/mobile mission views; home-based displayed/edit paths resolve; no overflow')
 b.close()
