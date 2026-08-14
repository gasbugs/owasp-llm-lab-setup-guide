import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infrastructure/scripts/student/forward-lab-ports.sh"


class ForwardLabPortsTests(unittest.TestCase):
    def test_all_learner_service_ports_are_forwarded(self):
        source = SCRIPT.read_text()
        for port in (
            3000,
            3001,
            3100,
            3200,
            4318,
            5000,
            8000,
            8001,
            8002,
            8010,
            8011,
            8012,
            8013,
            8014,
            8080,
            8501,
            11434,
            9090,
            9093,
            9400,
            13133,
            18002,
            18012,
            18080,
            18090,
            18091,
            18092,
            18200,
        ):
            self.assertIn(str(port), source)

    def test_sessions_use_ssm_and_are_cleaned_up_together(self):
        source = SCRIPT.read_text()
        self.assertIn("AWS-StartPortForwardingSession", source)
        self.assertIn("trap cleanup EXIT INT TERM", source)
        self.assertIn('kill "${PIDS[@]}"', source)


if __name__ == "__main__":
    unittest.main()
