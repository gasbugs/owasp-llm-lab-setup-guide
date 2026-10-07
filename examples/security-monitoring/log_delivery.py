"""Replay committed incident logs to Alloy; acknowledgements never erase audit rows."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from contextlib import contextmanager
from urllib.request import Request, urlopen


class LogDelivery:
    def __init__(self, path: Path, endpoint: str) -> None:
        self.path, self.endpoint = path, endpoint
        self.stopping = threading.Event()
        self.worker = None

    @contextmanager
    def connect(self):
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

    @staticmethod
    def prepare(db):
        db.executescript("""
          CREATE TABLE IF NOT EXISTS log_outbox (
            event_id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS log_delivery_statistics (
            name TEXT PRIMARY KEY, value INTEGER NOT NULL);
          INSERT OR IGNORE INTO log_delivery_statistics VALUES ('delivered', 0);
          INSERT OR IGNORE INTO log_delivery_statistics VALUES ('failures', 0);
        """)

    def flush_once(self) -> bool:
        with self.connect() as db:
            row = db.execute("SELECT event_id,body FROM log_outbox ORDER BY created LIMIT 1").fetchone()
        if row is None:
            return False
        record = json.loads(row[1])
        trace_id = record.get("trace_id")
        entry = {"timeUnixNano": str(record["timestamp_ms"] * 1000000),
                 "severityNumber": {"critical": 21, "high": 17, "warning": 13}.get(record["severity"], 9),
                 "severityText": record["severity"].upper(),
                 "body": {"stringValue": row[1]},
                 "attributes": [{"key": "event_id", "value": {"stringValue": row[0]}}]}
        if isinstance(trace_id, str) and len(trace_id) == 32 and trace_id != "0"*32:
            entry["traceId"] = trace_id
        payload = {"resourceLogs": [{"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "llm-security-gateway"}},
            {"key": "service.version", "value": {"stringValue": "3.0.0"}}]},
            "scopeLogs": [{"scope": {"name": "owasp_llm.security"}, "logRecords": [entry]}]}]}
        try:
            request = Request(f"{self.endpoint}/v1/logs", data=json.dumps(payload).encode(),
                              method="POST", headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                result = json.loads(response.read() or b"{}")
                if int(result.get("partialSuccess", {}).get("rejectedLogRecords", 0)):
                    raise ValueError("OTLP rejected records")
        except Exception:
            with self.connect() as db:
                db.execute("UPDATE log_delivery_statistics SET value=value+1 WHERE name='failures'")
            return False
        with self.connect() as db:
            db.execute("DELETE FROM log_outbox WHERE event_id=?", (row[0],))
            db.execute("UPDATE log_delivery_statistics SET value=value+1 WHERE name='delivered'")
        return True

    def run(self):
        while not self.stopping.is_set():
            try:
                delivered = self.flush_once()
            except Exception:
                delivered = False
                print('{"event":"log_delivery_storage_error"}', flush=True)
            if not delivered:
                self.stopping.wait(1)

    def start(self):
        if self.endpoint:
            self.worker = threading.Thread(target=self.run, daemon=True)
            self.worker.start()

    def stop(self):
        self.stopping.set()
        if self.worker:
            self.worker.join(timeout=4)

    def metrics(self) -> str:
        with self.connect() as db:
            values = dict(db.execute("SELECT name,value FROM log_delivery_statistics"))
            count, oldest = db.execute("SELECT COUNT(*),MIN(created) FROM log_outbox").fetchone()
        rows = [f'llm_log_delivery_total{{result="{key}"}} {value}' for key, value in values.items()]
        rows += [f"llm_log_pending_events {count}",
                 f"llm_log_oldest_pending_seconds {max(0,time.time()-oldest) if oldest else 0}"]
        return "\n".join(rows)+"\n"
