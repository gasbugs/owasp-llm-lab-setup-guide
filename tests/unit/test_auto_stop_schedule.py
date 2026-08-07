import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class AutoStopScheduleTests(unittest.TestCase):
    def test_default_schedule_stops_instances_at_1800_kst(self):
        variables = (ROOT / "infrastructure/terraform/variables.tf").read_text()
        schedules = (ROOT / "infrastructure/terraform/auto_stop.tf").read_text()

        self.assertIn('default     = "daily_1800"', variables)
        self.assertIn('daily_1800 = {', schedules)
        self.assertIn('"daily-1800-kst" = "cron(0 9 * * ? *)"', schedules)

    def test_legacy_1730_schedule_remains_available(self):
        variables = (ROOT / "infrastructure/terraform/variables.tf").read_text()
        schedules = (ROOT / "infrastructure/terraform/auto_stop.tf").read_text()

        self.assertIn('"daily_1730"', variables)
        self.assertIn('daily_1730 = {', schedules)


if __name__ == "__main__":
    unittest.main()
