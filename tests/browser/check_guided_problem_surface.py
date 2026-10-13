"""Current 24-mission problem-surface gate using the shared UI regressions.

The previous inline suite assumed 22 missions, hidden desktop tooltips and old
pane layouts. The shared suite tests current menu transitions, recorded-report
restoration and both-theme information/status rendering on the real assets.
Implementation and provider checks remain in the Practice service CI jobs.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    folder = args.output.parent / "ui-regressions"
    subprocess.run([sys.executable, str(Path(__file__).with_name("check_guided_ui_regressions.py")),
                    "--output", str(folder)], check=True)
    args.output.write_text((folder / "summary.json").read_text())


if __name__ == "__main__":
    main()
