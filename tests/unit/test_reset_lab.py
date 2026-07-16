"""Contracts for the learner-facing allowlisted reset command."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESET_LAB = ROOT / "infrastructure/scripts/student/reset-lab"


class ResetLabTest(unittest.TestCase):
    def run_reset(self, lab_id: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            mock_bin = Path(directory)
            log = mock_bin / "systemctl.log"
            (mock_bin / "id").write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = -u ]; then echo 1000; exit 0; fi\n"
                "exec /usr/bin/id \"$@\"\n",
                encoding="utf-8",
            )
            (mock_bin / "systemctl").write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$MOCK_SYSTEMCTL_LOG\"\n",
                encoding="utf-8",
            )
            (mock_bin / "curl").write_text(
                "#!/bin/sh\n"
                "for value in \"$@\"; do url=\"$value\"; done\n"
                "case \"$url\" in\n"
                "  *:11434/api/tags) printf '%s\\n' '{\"models\":[]}' ;;\n"
                "  *:8001/healthz) printf '%s\\n' '{\"ok\":true,\"tools\":[\"delete_animal\"]}' ;;\n"
                "  *:8013/healthz) printf '%s\\n' '{\"ok\":true,\"default_scenario\":\"day5\"}' ;;\n"
                "  *) printf '%s\\n' '{\"ok\":true}' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            for name in ("id", "systemctl", "curl"):
                (mock_bin / name).chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{mock_bin}:{env['PATH']}",
                    "MOCK_SYSTEMCTL_LOG": str(log),
                    "RESET_LAB_READY_ATTEMPTS": "1",
                    "RESET_LAB_READY_SLEEP_SECONDS": "1",
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                }
            )
            result = subprocess.run(
                ["bash", str(RESET_LAB), lab_id],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return result, calls

    def test_llm06_restarts_exact_agent_unit_and_emits_raw_health(self) -> None:
        result, calls = self.run_reset("llm06")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls, ["--user restart lab-day3-vuln-agent.service"]
        )
        self.assertIn("LLM06_READY_URL=http://127.0.0.1:8001/healthz", result.stdout)
        self.assertIn('{"ok":true,"tools":["delete_animal"]}', result.stdout)

    def test_simple_allowlist_ids_restart_only_their_exact_units(self) -> None:
        cases = {
            "llm01b": (
                "lab-day1-vuln-rag.service",
                "LLM01B_READY_URL=http://127.0.0.1:8000/healthz",
            ),
            "llm04": (
                "lab-day2-vuln-rag.service",
                "LLM04_READY_URL=http://127.0.0.1:8010/healthz",
            ),
            "llm05": (
                "lab-day3-vuln-rag.service",
                "LLM05_READY_URL=http://127.0.0.1:8011/healthz",
            ),
            "llmgoat": (
                "lab-llmgoat.service",
                "LLMGOAT_READY_URL=http://127.0.0.1:5000/healthz",
            ),
        }
        for lab_id, (unit, ready_line) in cases.items():
            with self.subTest(lab_id=lab_id):
                result, calls = self.run_reset(lab_id)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [f"--user restart {unit}"])
                self.assertIn(ready_line, result.stdout)
                self.assertIn('{"ok":true}', result.stdout)

    def test_llm10_uses_day5_ollama_day5_systemd_order(self) -> None:
        result, calls = self.run_reset("llm10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                "--user restart lab-day5-vuln-rag.service",
                "--user restart lab-ollama.service",
                "--user restart lab-day5-vuln-rag.service",
            ],
        )
        self.assertIn("OLLAMA_READY_URL=http://127.0.0.1:11434/api/tags", result.stdout)
        self.assertIn("LLM10_READY_URL=http://127.0.0.1:8013/healthz", result.stdout)
        self.assertIn('{"models":[]}', result.stdout)
        self.assertIn('{"ok":true,"default_scenario":"day5"}', result.stdout)

    def test_unknown_lab_fails_before_any_service_action(self) -> None:
        result, calls = self.run_reset("not-a-lab")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])
        self.assertIn("not allowlisted", result.stderr)

    def test_reset_command_contains_no_learner_storage_mutation(self) -> None:
        source = RESET_LAB.read_text(encoding="utf-8")
        self.assertNotIn("rm ", source)
        self.assertNotIn("rm\n", source)
        self.assertNotIn("/home/ubuntu/work", source)
        self.assertNotIn("/home/ubuntu/.LLMGoat", source)
        self.assertNotIn("/home/ubuntu/ollama-models", source)
        self.assertNotIn("podman restart", source)
        self.assertIn("systemctl --user restart", source)


if __name__ == "__main__":
    unittest.main()
