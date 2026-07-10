"""Regression tests for E2E loopback URL validation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/e2e/lib/require_loopback_url.py"
SPEC = importlib.util.spec_from_file_location("require_loopback_url", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LoopbackUrlGuardTest(unittest.TestCase):
    def test_accepts_only_explicit_loopback_origins(self) -> None:
        self.assertTrue(MODULE.is_strict_loopback_url("http://localhost:8000"))
        self.assertTrue(MODULE.is_strict_loopback_url("http://127.0.0.1:8001"))
        self.assertTrue(MODULE.is_strict_loopback_url("http://[::1]:5000"))

    def test_rejects_userinfo_private_network_bypass(self) -> None:
        self.assertFalse(
            MODULE.is_strict_loopback_url(
                "http://localhost:8000@169.254.169.254/latest/meta-data/"
            )
        )

    def test_rejects_credentials_paths_queries_and_invalid_ports(self) -> None:
        rejected = (
            "https://localhost:8000",
            "http://user@localhost:8000",
            "http://localhost:8000/api",
            "http://localhost:8000?next=http://example.com",
            "http://localhost",
            "http://localhost:99999",
            "http://127.0.0.2:8000",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(MODULE.is_strict_loopback_url(value))


if __name__ == "__main__":
    unittest.main()
