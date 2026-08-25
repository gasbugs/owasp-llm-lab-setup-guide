from __future__ import annotations

import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


class ApplicationAuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        control = Path(__file__).resolve().parents[1]
        gateway = control / "application-gateway"
        sys.path.insert(0, str(gateway))
        telemetry = types.ModuleType("telemetry")
        telemetry.configure_telemetry = lambda app, service_name: None
        telemetry.current_trace_id = lambda: None
        sys.modules["telemetry"] = telemetry
        os.environ.update({
            "APPLICATION_INTERNAL_TOKEN": "test-app-to-hub",
            "AUTH_ADMIN_TOKEN": "test-auth-admin-token",
            "BEDROCK_GATEWAY_TOKEN": "test-bedrock-token",
            "AUTH_USERS_PATH": str(control / "policies/application-users.yaml"),
            "AUTH_STATE_DIR": str(Path(cls.temp.name) / "state"),
            "AUTH_ISSUER": "https://testserver",
            "AUTH_ALLOWED_ORIGINS": "https://testserver",
            "AUTH_EVENT_SINK": "stdout",
            "AUTH_SECURE_COOKIE": "true",
        })
        cls.server = importlib.import_module("server")
        cls.client = TestClient(cls.server.app, base_url="https://testserver")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_login_and_jwks(self) -> None:
        response = self.client.post(
            "/.well-known/login",
            json={"username": "public-reader", "password": "public-reader-demo"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["token_type"], "Bearer")
        self.assertIn("__Host-lab_refresh", response.cookies)
        self.assertEqual(
            self.client.get("/.well-known/jwks.json").json()["keys"][0]["alg"],
            "RS256",
        )

    def test_wrong_password_is_401(self) -> None:
        response = self.client.post(
            "/.well-known/login",
            json={"username": "public-reader", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 401)

    def test_refresh_requires_trusted_origin_and_rotates(self) -> None:
        login = self.client.post(
            "/.well-known/login",
            json={"username": "public-reader", "password": "public-reader-demo"},
        )
        first_access = login.json()["access_token"]
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 403)
        refreshed = self.client.post(
            "/api/auth/refresh", headers={"Origin": "https://testserver"}
        )
        self.assertEqual(refreshed.status_code, 200)
        self.assertNotEqual(refreshed.json()["access_token"], first_access)

    def test_logout_revokes_access_token(self) -> None:
        login = self.client.post(
            "/.well-known/login",
            json={"username": "public-reader", "password": "public-reader-demo"},
        )
        token = login.json()["access_token"]
        logout = self.client.post(
            "/api/auth/logout",
            headers={"Origin": "https://testserver", "Authorization": f"Bearer {token}"},
        )
        self.assertEqual(logout.status_code, 204)
        with self.assertRaises(self.server.AuthError):
            self.server.auth_service.verify_access(token)


if __name__ == "__main__":
    unittest.main()
