"""Repository-level licensing and third-party scope regression tests."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLYFORM_NONCOMMERCIAL_1_0_0_SHA256 = (
    "c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5"
)


class RepositoryLicenseTest(unittest.TestCase):
    def test_polyform_license_matches_the_unmodified_official_text(self) -> None:
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual(digest, POLYFORM_NONCOMMERCIAL_1_0_0_SHA256)

    def test_dual_license_and_mit_transition_are_disclosed(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        commercial = (ROOT / "COMMERCIAL-LICENSE.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
        self.assertIn("PolyForm Noncommercial License 1.0.0", readme)
        self.assertIn("상업용 라이선스", readme)
        self.assertIn("Earlier MIT releases", commercial)
        self.assertIn("previously distributed under the MIT License", notice)

    def test_upstream_licenses_are_not_relicensed(self) -> None:
        third_party = (ROOT / "THIRD-PARTY-LICENSES.md").read_text(encoding="utf-8")
        llmgoat_dockerfile = (ROOT / "docker/llmgoat/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("SECFORCE LLMGoat", third_party)
        self.assertIn("GPL-3.0", third_party)
        self.assertIn("GPL-3.0", llmgoat_dockerfile)
        self.assertNotIn("LLMGoat (Apache 2.0)", llmgoat_dockerfile)


if __name__ == "__main__":
    unittest.main()
