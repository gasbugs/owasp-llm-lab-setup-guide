"""Run existing isolated publishers with Starter and reference fixture inputs."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PRACTICES = ("P01", "P02", "P03", "P04", "P12", "P17", "P18", "P19", "P20")


def commands(practice, output, python):
    browser = ["--browser-python", python]
    prefix = [python, "tests/e2e/"]
    fixtures = "tests/e2e/fixtures/"
    result = []
    for starter in (True, False):
        variant = "starter" if starter else "solution"
        path = str(output / variant)
        if practice in ("P01", "P02", "P03", "P04"):
            fixture = {"P01": "p01_gateway.py", "P02": "p02_document.py",
                       "P03": "p03_search_current.py", "P04": "p04_invoke_guarded.py"}[practice]
            args = (["--starter"] if starter else ["--source", fixtures + fixture]) + browser
            name = "check_guided_" + practice.lower() + "_live.py"
        elif practice == "P12":
            name = "check_guided_p12_products.py"
            args = ["--starter", "--deployment", *browser] if starter else []
        elif practice in ("P17", "P19"):
            name = "check_guided_" + practice.lower() + "_implementation.py"
            fixture = "p17_instrumentation.py" if practice == "P17" else "p19_analysis.py"
            source = fixtures + fixture
            if starter:
                source = "llm-security-control-plane/guided-labs/" + (
                    "h17-telemetry/instrumentation.py" if practice == "P17" else "h19-incident-investigation/investigation.py")
            args = [source, "--tcp-verifier", *browser]
            if starter:
                args.append("--starter")
        elif practice == "P18":
            name = "check_guided_p18_markdown.py"
            args = ["--source", fixtures + "p18/queries.yaml", "--tcp-verifier", *browser]
            if starter:
                args.append("--starter")
        else:
            name = "check_guided_p20_products.py"
            args = ["--server-run", "--tcp-verifier", *browser]
            if starter:
                args.append("--starter")
        result.append([prefix[0], prefix[1] + name, *args, "--output", path])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("practice", choices=PRACTICES)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output directory; preserve previous evidence")
    args.output.mkdir(parents=True)
    for command in commands(args.practice, args.output.resolve(), sys.executable):
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
