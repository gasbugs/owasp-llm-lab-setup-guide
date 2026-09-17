"""Publish shared navigation into standalone app images; --check detects drift."""
from pathlib import Path
import argparse
import re

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [ROOT / f"docker/{app}/app/templates/index.html"
           for app in ("vuln-rag", "vuln-agent")]


def sync(*, check=False):
    navigation = (ROOT / "docker/shared-ui/navigation.html").read_text().strip()
    changed = []
    for target in TARGETS:
        source = target.read_text()
        updated, count = re.subn(r'<nav id="lab-navigation".*?</nav>',
                                lambda _: navigation, source, flags=re.S)
        if count != 1:
            raise ValueError(f"expected one navigation in {target}")
        if updated != source:
            changed.append(str(target.relative_to(ROOT)))
            if not check:
                target.write_text(updated)
    return changed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    changed = sync(check=args.check)
    if args.check and changed:
        parser.exit(1, "Run python tools/sync_platform_ui.py: " + ", ".join(changed) + "\n")
