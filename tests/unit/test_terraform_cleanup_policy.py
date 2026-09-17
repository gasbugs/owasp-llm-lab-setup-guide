import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class TerraformCleanupPolicyTests(unittest.TestCase):
    def test_stack_does_not_create_scheduled_auto_stop_resources(self):
        terraform = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "infrastructure/terraform").glob("*.tf")
        )

        self.assertNotIn("aws_lambda_function", terraform)
        self.assertNotIn("aws_cloudwatch_event_rule", terraform)
        self.assertNotIn("archive_file", terraform)
        self.assertNotIn("enable_auto_stop", terraform)

    def test_explicit_stop_command_scales_asg_to_zero(self):
        outputs = (ROOT / "infrastructure/terraform/outputs.tf").read_text(
            encoding="utf-8"
        )
        stop = (ROOT / "infrastructure/scripts/student/stop-lab.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--desired-capacity 0", outputs)
        self.assertIn("--desired-capacity 0", stop)
        self.assertIn("root EBS가 삭제됩니다", stop)


if __name__ == "__main__":
    unittest.main()
