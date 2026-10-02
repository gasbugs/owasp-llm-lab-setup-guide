"""Exercise the real shell helpers with an AWS CLI double; no AWS resources."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "infrastructure/scripts/student"


class StudentEc2LifecycleTests(unittest.TestCase):
    def run_helper(self, action, rows, failure="", course=""):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            aws = path / "aws"
            aws.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if os.environ.get("FAILURE") and os.environ["FAILURE"] in args:
    sys.exit(1)
if args[:2] == ["ec2", "describe-instances"]:
    print(os.environ["ROWS"])
else:
    print("{}")
''')
            aws.chmod(0o755)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}",
                       AWS_PROFILE="test-profile", AWS_REGION="us-east-1",
                       COURSE_ID=course, ROWS=json.dumps(rows), FAILURE=failure,
                       CALLS=str(path / "calls"))
            result = subprocess.run(["bash", str(SCRIPTS / f"{action}-lab.sh")],
                                    env=env, text=True, capture_output=True)
            calls = [json.loads(line) for line in (path / "calls").read_text().splitlines()]
            return result, calls

    def test_start_and_stop_target_same_instance_and_wait(self):
        for action, state in (("start", "running"), ("stop", "stopped")):
            with self.subTest(action=action):
                result, calls = self.run_helper(action, [{"id": "i-0123456789abcdef0", "asg": None}], course="course-a")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Name=tag:Course,Values=course-a", calls[1])
                self.assertIn("Name=instance-state-name,Values=pending,running,stopping,stopped", calls[1])
                self.assertEqual(calls[2][:2], ["ec2", f"{action}-instances"])
                self.assertEqual(calls[3][:3], ["ec2", "wait", f"instance-{state}"])
                self.assertEqual(calls[2][-1], "i-0123456789abcdef0")
                self.assertEqual(calls[3][-1], "i-0123456789abcdef0")
                self.assertEqual(len(calls), 4)

    def test_ambiguous_missing_legacy_and_malformed_targets_never_mutate(self):
        for rows in ([], [{"id": "i-1"}, {"id": "i-2"}],
                     [{"id": "i-1", "asg": "legacy-asg"}], [{"id": "None"}]):
            for action in ("start", "stop"):
                with self.subTest(rows=rows, action=action):
                    result, calls = self.run_helper(action, rows)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(calls), 2)

    def test_cli_errors_propagate_without_false_completion(self):
        for failure, count in (("get-caller-identity", 1), ("describe-instances", 2),
                               ("stop-instances", 3), ("wait", 4)):
            with self.subTest(failure=failure):
                result, calls = self.run_helper("stop", [{"id": "i-1", "asg": None}], failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("stopped:", result.stdout)
                self.assertEqual(len(calls), count)
