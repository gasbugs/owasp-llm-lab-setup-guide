from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "application-gateway"))
from auth import AuthService, InvalidCredentials, InvalidToken, TokenReplay


class ApplicationAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.users = self.root / "users.yaml"
        self.users.write_text(
            """users:
  reader:
    password_hash: pbkdf2_sha256$600000$MDEyMzQ1Njc4OWFiY2RlZg$Pu5R-46DItg8O-EfKSsWJa2dMUEumoPhthp_Mx_VC-0
    roles: [public_reader]
    allowed_classifications: [public]
    allowed_purposes: [public_information]
""",
            encoding="utf-8",
        )
        self.auth = AuthService(
            str(self.users),
            str(self.root / "state"),
            "https://issuer.example",
            "application-audience",
            access_ttl=300,
            refresh_ttl=1800,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_login_issues_verified_access_token(self) -> None:
        pair = self.auth.authenticate_password("reader", "demo-password")
        claims = self.auth.verify_access(pair["access_token"])

        self.assertEqual(claims["sub"], "reader")
        self.assertEqual(claims["roles"], ["public_reader"])
        self.assertEqual(claims["iss"], "https://issuer.example")
        self.assertEqual(claims["aud"], "application-audience")

    def test_wrong_password_is_rejected(self) -> None:
        with self.assertRaises(InvalidCredentials):
            self.auth.authenticate_password("reader", "wrong")

    def test_tampered_token_is_rejected(self) -> None:
        token = self.auth.issue_pair("reader")["access_token"]
        head, body, signature = token.split(".")
        tampered = f"{head}.{body[:-1]}{'A' if body[-1] != 'A' else 'B'}.{signature}"
        with self.assertRaises(InvalidToken):
            self.auth.verify_access(tampered)

    def test_refresh_rotates_and_reuse_is_detected(self) -> None:
        first = self.auth.issue_pair("reader")
        second = self.auth.refresh(first["refresh_token"])

        self.assertEqual(self.auth.verify_access(second["access_token"])["sub"], "reader")
        with self.assertRaises(TokenReplay):
            self.auth.refresh(first["refresh_token"])

    def test_key_rotation_keeps_previous_public_key(self) -> None:
        first = self.auth.issue_pair("reader")
        old_kid = jwt.get_unverified_header(first["access_token"])["kid"]
        new_kid = self.auth.rotate_key()
        second = self.auth.issue_pair("reader")

        self.assertNotEqual(old_kid, new_kid)
        self.assertEqual(self.auth.verify_access(first["access_token"])["sub"], "reader")
        self.assertEqual(jwt.get_unverified_header(second["access_token"])["kid"], new_kid)
        self.assertEqual({key["kid"] for key in self.auth.jwks()["keys"]}, {old_kid, new_kid})

    def test_revoked_access_token_fails_closed(self) -> None:
        pair = self.auth.issue_pair("reader")
        self.auth.revoke(pair["access_token"], "access")
        with self.assertRaises(InvalidToken):
            self.auth.verify_access(pair["access_token"])


if __name__ == "__main__":
    unittest.main()
