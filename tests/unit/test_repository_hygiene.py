"""Fail CI when public examples contain likely credentials or personal contact data."""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TFVARS_EXAMPLE = ROOT / "infrastructure" / "terraform" / "terraform.tfvars.example"

EMAIL_RE = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,}))(?![\w.-])"
)
ALLOWED_EXAMPLE_DOMAINS = {"example.com", "company.com"}

# Split fixed prefixes so this source file does not trigger its own detector.
SECRET_PATTERNS = {
    "AWS access key": re.compile("AK" + r"IA[0-9A-Z]{16}"),
    "GitHub token": re.compile("gh" + r"[pousr]_[A-Za-z0-9]{20,}"),
    "private key": re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def repository_text_files() -> list[Path]:
    files: list[Path] = []
    listed = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    for raw_relative in listed.split(b"\0"):
        if not raw_relative:
            continue
        path = ROOT / raw_relative.decode("utf-8", errors="surrogateescape")
        if not path.is_file():
            continue
        if "results" in path.parts and "e2e" in path.parts:
            continue
        if path.stat().st_size > 2_000_000:
            continue
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files.append(path)
    return files


class RepositoryHygieneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = repository_text_files()

    def test_terraform_example_uses_neutral_contact_placeholders(self) -> None:
        text = TFVARS_EXAMPLE.read_text(encoding="utf-8")
        self.assertRegex(text, r'allowed_ingress_cidr\s*=\s*"127\.0\.0\.1/32"')
        self.assertRegex(text, r'alert_email\s*=\s*"[A-Za-z0-9._%+-]+@example\.com"')

    def test_no_likely_secrets_in_public_text_files(self) -> None:
        findings: list[str] = []
        for path in self.files:
            text = path.read_text(encoding="utf-8")
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(text):
                    findings.append(f"{path.relative_to(ROOT)}: {label}")
        self.assertEqual(findings, [], "likely secrets found:\n" + "\n".join(findings))

    def test_emails_use_documentation_domains(self) -> None:
        findings: list[str] = []
        for path in self.files:
            text = path.read_text(encoding="utf-8")
            for match in EMAIL_RE.finditer(text):
                address, domain = match.groups()
                if domain.lower() not in ALLOWED_EXAMPLE_DOMAINS:
                    findings.append(f"{path.relative_to(ROOT)}: {address}")
        self.assertEqual(findings, [], "non-placeholder emails found:\n" + "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
