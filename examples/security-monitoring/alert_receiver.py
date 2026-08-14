#!/usr/bin/env python3
"""Small lab webhook that proves Alertmanager notification delivery."""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Gauge, generate_latest


app = FastAPI(title="Module 08 Alert Receiver", version="1.0.0")
LOCK = threading.Lock()
NOTIFICATIONS: list[dict[str, Any]] = []
DELIVERIES = Counter(
    "llm_alert_notifications_received_total",
    "Alertmanager webhook notifications accepted by status.",
    ["status"],
)
LAST_DELIVERY = Gauge(
    "llm_alert_notification_last_received_timestamp_seconds",
    "Unix timestamp of the most recent Alertmanager webhook delivery.",
)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "service": "module08-alert-receiver"}


@app.post("/api/alerts")
def receive_alert(payload: dict[str, Any]) -> dict[str, Any]:
    status = str(payload.get("status") or "unknown")
    with LOCK:
        NOTIFICATIONS.append(payload)
        if len(NOTIFICATIONS) > 100:
            del NOTIFICATIONS[:-100]
    DELIVERIES.labels(status=status).inc()
    LAST_DELIVERY.set(time.time())
    print(json.dumps({"event": "alert_notification", **payload}, separators=(",", ":")), flush=True)
    return {"accepted": True, "status": status, "alerts": len(payload.get("alerts", []))}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> bytes:
    return generate_latest()


@app.get("/api/notifications")
def notifications() -> dict[str, Any]:
    with LOCK:
        values = list(NOTIFICATIONS)
    return {"count": len(values), "notifications": values}


@app.delete("/api/notifications")
def clear_notifications() -> dict[str, Any]:
    with LOCK:
        deleted = len(NOTIFICATIONS)
        NOTIFICATIONS.clear()
    return {"deleted": deleted}
