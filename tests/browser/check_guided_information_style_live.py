"""Measure rendered information/status contrast across all missions and both themes."""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

ORIGIN = os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097")
ARTIFACTS = Path(os.getenv("GUIDED_UI_ARTIFACTS", "/tmp/guided-ui-theme-check"))
ARTIFACTS.mkdir(parents=True, exist_ok=True)
MEASURE = r"""els=>els.map(e=>{
  const rgba=s=>s.match(/[\d.]+/g).map(Number);
  const layer=(a,b)=>a.slice(0,3).map((v,i)=>v*(a[3]??1)+b[i]*(1-(a[3]??1)));
  function background(el){if(!el)return [255,255,255];return layer(rgba(getComputedStyle(el).backgroundColor),background(el.parentElement));}
  const s=getComputedStyle(e),bg=background(e),fg=layer(rgba(s.color),bg);
  const luminance=v=>v.map(x=>x/255).map(x=>x<=.04045?x/12.92:Math.pow((x+.055)/1.055,2.4)).reduce((sum,x,i)=>sum+x*[.2126,.7152,.0722][i],0);
  const a=luminance(fg),b=luminance(bg),r=e.getBoundingClientRect();
  return {id:e.id||e.className,text:e.textContent.trim().slice(0,60),color:s.color,background:bg,
    contrast:(Math.max(a,b)+.05)/(Math.min(a,b)+.05),width:r.width,x:r.x};
})"""

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    errors, mutations, measurements = [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda request: mutations.append(request.url) if request.method == "POST" else None)
    page.goto(ORIGIN, wait_until="networkidle")
    missions = page.evaluate("missionOrder")
    before = page.evaluate('fetch("/api/progress").then(r=>r.json())')
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 1000})
        for theme in ("light", "dark"):
            page.evaluate("theme=>applyTheme(theme)", theme)
            for mission in missions:
                page.evaluate('id=>{if(id==="P00")selectWorkspace("tutorial");'
                              'else selectTab(practiceGroups.findIndex(g=>g.includes(id)),id);}', mission)
                for pane in ("experience", "grade"):
                    page.evaluate('({id,pane})=>{if(id==="P00")selectTutorialPane(pane);'
                                  'else if(id==="P01")selectP01Pane(pane==="grade"?"grade":"model");'
                                  'else selectModelCallPane(pane,false);}', {"id": mission, "pane": pane})
                    if pane == "grade":
                        # These sample statuses test colours only, not a security decision.
                        page.evaluate('id=>{const cases=["PASS","HIT","ERR","미실행"].map(status=>({case_id:status+" 표시 샘플",status}));'
                                      'if(id==="P00")displayTutorialGrade({completed:false,cases});'
                                      'else renderReportedCases({activity_id:id,result:{cases}});}', mission)
                    selectors = ".action-tooltip:visible,.action-tip:visible,.action-help-summary:visible,.case-badge:visible,.case-details > summary:visible"
                    values = page.locator(selectors).evaluate_all(MEASURE)
                    assert values, (width, theme, mission, pane)
                    for item in values:
                        assert item["contrast"] >= 4.5, (width, theme, mission, pane, item)
                        assert item["width"] > 0 and item["x"] >= 0 and item["x"]+item["width"] <= width+1, (mission, item)
                        measurements.append({"width": width, "theme": theme, "mission": mission, "pane": pane, **item})
                    if pane == "grade":
                        assert page.locator(".case-badge:visible").all_text_contents() == ["PASS", "HIT", "ERR", "미실행"]
                    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (mission, width, theme)
            page.evaluate('selectTab(1,"P23");selectModelCallPane("experience")')
            page.locator("#h23-chat-help").screenshot(path=str(ARTIFACTS / f"information-{theme}-{width}.png"))
    assert before == page.evaluate('fetch("/api/progress").then(r=>r.json())')
    assert not errors and not mutations, (errors, mutations)
    (ARTIFACTS / "theme-contrast.json").write_text(json.dumps(measurements, ensure_ascii=False, indent=2))
    print(f"PASS: {len(missions)} missions × 2 panes × 2 widths × 2 themes; {len(measurements)} text contrasts >= 4.5; all four status labels visible; no overflow/writes")
    browser.close()
