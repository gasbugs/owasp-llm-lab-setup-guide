"""Application-owned JWT issuer, verifier, refresh rotation, and revocation."""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class AuthError(ValueError):
    pass


class InvalidCredentials(AuthError):
    pass


class InvalidToken(AuthError):
    pass


class TokenReplay(InvalidToken):
    pass


def _b64uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class AuthService:
    def __init__(
        self,
        users_path: str,
        state_dir: str,
        issuer: str,
        audience: str,
        access_ttl: int = 300,
        refresh_ttl: int = 1800,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir = self.state_dir / "keys"
        self.keys_dir.mkdir(exist_ok=True)
        self.db_path = self.state_dir / "auth.db"
        with open(users_path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        self.users = document.get("users", {})
        if not self.users:
            raise RuntimeError("application users policy must define at least one user")
        self._initialize_database()
        self.active_kid = self._ensure_active_key()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS tokens (
                    jti TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    replaced_by TEXT
                )"""
            )

    def _active_key_file(self) -> Path:
        return self.state_dir / "active-kid"

    def _ensure_active_key(self) -> str:
        marker = self._active_key_file()
        if marker.exists():
            kid = marker.read_text(encoding="utf-8").strip()
            if kid and (self.keys_dir / f"{kid}.pem").exists():
                return kid
        return self.rotate_key()

    def rotate_key(self) -> str:
        kid = f"auth-{int(time.time())}-{secrets.token_hex(4)}"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path = self.keys_dir / f"{kid}.pem"
        key_path.write_bytes(pem)
        os.chmod(key_path, 0o600)
        self._active_key_file().write_text(f"{kid}\n", encoding="utf-8")
        self.active_kid = kid
        return kid

    def _private_key(self, kid: str):
        path = self.keys_dir / f"{kid}.pem"
        if not path.exists():
            raise InvalidToken("unknown-signing-key")
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        keys = []
        for path in sorted(self.keys_dir.glob("*.pem")):
            public_numbers = self._private_key(path.stem).public_key().public_numbers()
            keys.append({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": path.stem,
                "n": _b64uint(public_numbers.n),
                "e": _b64uint(public_numbers.e),
            })
        return {"keys": keys}

    def authenticate_password(self, username: str, password: str) -> dict[str, Any]:
        user = self.users.get(username)
        if not user or not secrets.compare_digest(str(user.get("password", "")), password):
            raise InvalidCredentials("invalid-username-or-password")
        return self.issue_pair(username)

    def _claims(self, subject: str, token_type: str, ttl: int, jti: str) -> dict[str, Any]:
        now = int(time.time())
        user = self.users[subject]
        return {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": subject,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": jti,
            "typ": token_type,
            "roles": list(user.get("roles", [])),
            "allowed_classifications": list(user.get("allowed_classifications", [])),
            "allowed_purposes": list(user.get("allowed_purposes", [])),
        }

    def _encode(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims,
            self._private_key(self.active_kid),
            algorithm="RS256",
            headers={"kid": self.active_kid, "typ": "JWT"},
        )

    def _record(self, claims: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tokens(jti, token_type, subject, expires_at) VALUES(?,?,?,?)",
                (claims["jti"], claims["typ"], claims["sub"], claims["exp"]),
            )

    def issue_pair(self, subject: str) -> dict[str, Any]:
        access_claims = self._claims(subject, "access", self.access_ttl, str(uuid.uuid4()))
        refresh_claims = self._claims(subject, "refresh", self.refresh_ttl, str(uuid.uuid4()))
        self._record(access_claims)
        self._record(refresh_claims)
        return {
            "access_token": self._encode(access_claims),
            "refresh_token": self._encode(refresh_claims),
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "subject": subject,
            "access_jti": access_claims["jti"],
            "refresh_jti": refresh_claims["jti"],
        }

    def _decode(self, token: str, expected_type: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise InvalidToken("invalid-signing-header")
            public_key = self._private_key(str(header["kid"])).public_key()
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "typ"]},
            )
        except InvalidToken:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token-expired") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken("token-validation-failed") from exc
        if claims.get("typ") != expected_type:
            raise InvalidToken("wrong-token-type")
        subject = str(claims.get("sub"))
        user = self.users.get(subject)
        if not user or sorted(claims.get("roles", [])) != sorted(user.get("roles", [])):
            raise InvalidToken("principal-policy-mismatch")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT revoked_at FROM tokens WHERE jti=? AND token_type=?",
                    (claims["jti"], expected_type),
                ).fetchone()
        except sqlite3.Error as exc:
            raise InvalidToken("token-state-unavailable") from exc
        if row is None:
            raise InvalidToken("unknown-token-jti")
        if row["revoked_at"] is not None:
            if expected_type == "refresh":
                raise TokenReplay("refresh-token-reuse")
            raise InvalidToken("token-revoked")
        return claims

    def verify_access(self, token: str) -> dict[str, Any]:
        return self._decode(token, "access")

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        claims = self._decode(refresh_token, "refresh")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tokens SET revoked_at=? WHERE jti=? AND revoked_at IS NULL",
                (int(time.time()), claims["jti"]),
            )
            if cursor.rowcount != 1:
                raise TokenReplay("refresh-token-reuse")
        pair = self.issue_pair(str(claims["sub"]))
        with self._connect() as connection:
            connection.execute(
                "UPDATE tokens SET replaced_by=? WHERE jti=?",
                (pair["refresh_jti"], claims["jti"]),
            )
        return pair

    def revoke(self, token: str, expected_type: str) -> dict[str, Any]:
        claims = self._decode(token, expected_type)
        with self._connect() as connection:
            connection.execute(
                "UPDATE tokens SET revoked_at=? WHERE jti=?",
                (int(time.time()), claims["jti"]),
            )
        return claims
