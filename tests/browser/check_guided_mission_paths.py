"""Every mission displays its isolated learner files and apply command; no edits or grades."""
import os
from collections import defaultdict
from pathlib import Path

from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[2]
workspace_prefix = "~/owasp-llm-practice/"
manifest = defaultdict(list)
for line in (root / "tools/guided-practice-files.tsv").read_text().splitlines():
    if not line or line.startswith("#"):
        continue
    display, source, workspace_name, services = line.split("|")
    manifest[display].append((source, workspace_name, services.split(",")))

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(os.getenv("GUIDED_UI_BASE_URL", "http://127.0.0.1:28097"), wait_until="networkidle")
    count = 0
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 900})
        for mission in page.evaluate("missionOrder"):
            if mission == "P00":
                continue
            page.evaluate("(id)=>selectTab(practiceGroups.findIndex(g=>g.includes(id)),id)", mission)
            display = page.evaluate("id=>missionLabel(id)", mission)
            expected = manifest[display]
            assert expected, (mission, display)
            panel = page.locator("#h" + mission[1:] + "-work")
            text = panel.inner_text()
            apply = panel.locator('pre[data-code-title="코드 적용 · 파일 복사와 재생성"]')
            assert apply.count() == 1, (mission, display)
            command = apply.inner_text()
            assert "cd ~/owasp-llm-lab-setup-guide" in command, (mission, display)
            assert "up -d --no-deps --force-recreate" in command, (mission, display)
            for source, workspace_name, services in expected:
                assert (root / "llm-security-control-plane" / source).is_file(), (mission, source)
                assert f"vi {workspace_prefix}{workspace_name}" in text, (mission, workspace_name)
                assert (
                    f"install -m 0644 {workspace_prefix}{workspace_name} "
                    f".state/guided-practice-build/{source}"
                ) in command, (mission, workspace_name)
                for service in services:
                    assert service in command, (mission, service)
            gaps = panel.locator(".hands-on > div > :is(p:not(.label), ul, ol, pre, details) + h3").evaluate_all(
                "(headings)=>headings.map(h=>({title:h.textContent,gap:h.getBoundingClientRect().top-h.previousElementSibling.getBoundingClientRect().bottom}))"
            )
            for item in gaps:
                assert item["gap"] >= 24, (mission, width, item)
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), mission
            count += 1
    print(f"PASS: {count} desktop/mobile mission views; isolated workspace files and apply commands resolve; no overflow")
    browser.close()
