"""The copied learner command must apply exactly its manifest-owned artifact."""
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ApplyBlocks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.current = []
        self.blocks = []

    def handle_starttag(self, tag, attrs):
        if tag == "pre" and dict(attrs).get("data-code-title") == "코드 적용 · 파일 복사와 재생성":
            self.active = True
            self.current = []

    def handle_data(self, data):
        if self.active:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self.active:
            self.blocks.append("".join(self.current))
            self.active = False


class ApplyGuidanceTests(unittest.TestCase):
    def test_each_mission_has_copyable_direct_apply_command(self):
        html = (ROOT / "llm-security-control-plane/guided-control-center/index.html").read_text()
        self.assertNotIn("apply-guided-practice.sh P", html)
        parser = ApplyBlocks()
        parser.feed(html)
        rows = {}
        for line in (ROOT / "tools/guided-practice-files.tsv").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            display, source, workspace, services = line.split("|")
            rows.setdefault(display, []).append((source, workspace, services.split(",")))
        self.assertEqual(len(parser.blocks), len(rows))
        for display, entries in rows.items():
            matches = [block for block in parser.blocks if f"~/owasp-llm-practice/{entries[0][1]}" in block]
            self.assertEqual(len(matches), 1, display)
            block = matches[0]
            for source, workspace, services in entries:
                self.assertIn(
                    f"install -m 0644 ~/owasp-llm-practice/{workspace} .state/guided-practice-build/{source}",
                    block, display,
                )
                for service in services:
                    self.assertIn(f"build {service}" if len(services) == 1 else service, block, display)
                    self.assertIn(service, block.split("up -d --no-deps --force-recreate", 1)[1], display)
            self.assertEqual(subprocess.run(["bash", "-n"], input=block, text=True, capture_output=True).returncode, 0, display)


if __name__ == "__main__":
    unittest.main()
