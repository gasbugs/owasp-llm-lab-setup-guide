from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "examples/security-monitoring/generate_module10_traffic.py"
SPEC = importlib.util.spec_from_file_location("module10_traffic", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class TrafficGeneratorTests(unittest.TestCase):
    def test_all_scenarios_produce_bounded_metadata(self) -> None:
        results = []
        responses = {
            "normal": ("allow", None, True),
            "normal_operations": ("allow", None, True),
            "prohibited_secret": ("block", "input:prohibited:DEMO_API_KEY", False),
            "prompt_injection": ("block", "input:nova general safety input", False),
            "authorization_denied": ("block", "classification-not-authorized", False),
        }
        for scenario in MODULE.SCENARIOS:
            if scenario["name"] == "invalid_login":
                with patch.object(
                    MODULE,
                    "login",
                    return_value=(401, {"detail": "invalid username or password"}),
                ):
                    results.append(
                        MODULE.execute_scenario(
                            "http://application.test",
                            scenario,
                            "public-reader",
                            "public-reader-demo",
                        )
                    )
                continue
            decision, reason, upstream = responses[scenario["name"]]
            chat_response = {
                "request_id": f"request-{decision}",
                "trace_id": f"trace-{decision}",
                "application_decision": decision,
                "blocking_reason": reason,
                "upstream_called": upstream,
            }
            with patch.object(
                MODULE, "login", return_value=(200, {"access_token": "test-token"})
            ), patch.object(MODULE, "request_json", return_value=(200, chat_response)):
                results.append(
                    MODULE.execute_scenario(
                        "http://application.test",
                        scenario,
                        "public-reader",
                        "public-reader-demo",
                    )
                )
        self.assertEqual(
            [result["decision"] for result in results],
            ["allow", "allow", "block", "block", "block", "block"],
        )
        for result in results:
            self.assertNotIn("message", result)
            self.assertNotIn("access_token", result)
            self.assertNotIn("password", result)
            self.assertIn(result["http_status"], {200, 401})


if __name__ == "__main__":
    unittest.main()
