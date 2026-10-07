"""Bounded, metadata-only durable delivery to the authenticated event collector."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from contextlib import contextmanager
from urllib.request import Request, urlopen

FIELDS = {
    "user_id", "attempted_user_id", "client_ip", "client_ip_source", "http_method", "http_path",
    "event", "engine", "direction", "decision", "blocking_reason", "request_id",
    "trace_id", "guard_mode", "guard_model_calls", "upstream_called", "duration_ms",
    "entity_types", "stage_name", "stage_order", "policy_bundle_version",
    "assurance_profile", "classification", "subject_hash", "auth_action",
    "http_status", "source_service", "source_version", "occurred_at_ns",
    "input_hmac_sha256", "main_stop_reason", "model_id", "roles", "token_hash", "client_ip_hash", "application_stages", "application_policy_id", "retrieval_called",
}


class AuditDelivery:
    def __init__(self, path: Path, endpoint: str, token: str, identity_key: str,
                 capacity: int = 10000) -> None:
        self.path, self.endpoint, self.token = path, endpoint, token
        self.identity_key, self.capacity = identity_key, capacity
        self.stop_event = threading.Event()
        self.worker = None
        self.storage_errors = 0
        with self.connect() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS pending (
                event_id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL);
              CREATE TABLE IF NOT EXISTS statistics (
                name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            """)
            for name in ("accepted", "delivered", "failures", "rejected"):
                db.execute("INSERT OR IGNORE INTO statistics VALUES (?, 0)", (name,))

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def identity(self, value) -> str | None:
        if value is None:
            return None
        return hmac.new(self.identity_key.encode(), str(value).encode(), hashlib.sha256).hexdigest()

    def enqueue(self, payload: dict) -> str | None:
        event = {key: value for key, value in payload.items() if key in FIELDS}
        event_id = str(uuid.uuid4())
        event["event_id"] = event_id
        event.setdefault("occurred_at_ns", str(time.time_ns()))
        # Server-verified identity and transport peer accompany pseudonymous correlation keys. User content is never allowlisted.
        if "subject" in payload:
            event["subject_hash"] = self.identity(payload["subject"])
        if "client_ip" in payload:
            event["client_ip_hash"] = self.identity(payload["client_ip"])
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            size = db.execute("SELECT COUNT(*) FROM pending").fetchone()[0]
            if size >= self.capacity or len(body.encode()) > 16384:
                db.execute("UPDATE statistics SET value=value+1 WHERE name='rejected'")
                return None
            db.execute("INSERT INTO pending VALUES (?, ?, ?)", (event_id, body, time.time()))
            db.execute("UPDATE statistics SET value=value+1 WHERE name='accepted'")
        return event_id

    def flush_once(self) -> bool:
        with self.connect() as db:
            row = db.execute("SELECT event_id,body FROM pending ORDER BY created LIMIT 1").fetchone()
        if row is None:
            return False
        try:
            request = Request(self.endpoint, data=row[1].encode(), method="POST",
                              headers={"Content-Type": "application/json", "X-Telemetry-Token": self.token})
            with urlopen(request, timeout=3) as response:
                result = json.load(response)
                if result.get("delivery_event_id") != row[0]:
                    raise ValueError("collector acknowledgement mismatch")
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE statistics SET value=value+1 WHERE name='failures'")
            return False
        with self.connect() as db:
            db.execute("DELETE FROM pending WHERE event_id=?", (row[0],))
            db.execute("UPDATE statistics SET value=value+1 WHERE name='delivered'")
        return True

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                delivered = self.flush_once()
            except Exception:
                self.storage_errors += 1
                delivered = False
                print('{"event":"audit_delivery_storage_error"}', flush=True)
            if not delivered:
                self.stop_event.wait(1)

    def start(self) -> None:
        if self.endpoint and self.token and self.worker is None:
            self.worker = threading.Thread(target=self.run, daemon=True)
            self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=4)

    def metrics(self) -> str:
        try:
            with self.connect() as db:
                values = dict(db.execute("SELECT name,value FROM statistics"))
                count, oldest = db.execute("SELECT COUNT(*),MIN(created) FROM pending").fetchone()
        except Exception:
            return (f"llm_audit_database_available 0\n"
                    f"llm_audit_storage_errors_total {self.storage_errors}\n")
        rows = [f'llm_audit_delivery_total{{result="{name}"}} {value}' for name, value in values.items()]
        rows.extend((f"llm_audit_pending_events {count}",
                     f"llm_audit_oldest_pending_seconds {max(0, time.time()-oldest) if oldest else 0}",
                     "llm_audit_database_available 1",
                     f"llm_audit_storage_errors_total {self.storage_errors}"))
        return "\n".join(rows) + "\n"


class PublicTraceBoundary:
    """The public caller cannot choose server incident correlation or sampling."""
    def __init__(self, app):
        self.app = app

    def __getattr__(self, name):
        return getattr(self.app, name)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "headers": [(key, value) for key, value in scope.get("headers", [])
                                         if key.lower() not in {b"traceparent", b"tracestate", b"baggage"}]}
        await self.app(scope, receive, send)
