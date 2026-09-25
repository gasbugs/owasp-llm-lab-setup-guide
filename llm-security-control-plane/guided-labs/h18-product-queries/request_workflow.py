"""Provided P18 authorization fixture, not an LLM or prompt-injection detector.

The same handler processes allowed and denied actions. Telemetry follows the
policy branch actually taken; the downstream function records its own calls.
"""

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

import httpx
import yaml

from query_execution import execute_queries


def wait_for_scrape(after_ns, *, client=None, timeout=10):
    """Readiness only: never use this infrastructure query to grade learner PromQL."""
    owned = client is None
    client = client or httpx.Client(timeout=2, trust_env=False)
    deadline = time.monotonic() + timeout
    try:
        while True:
            response = client.get('http://prometheus:9090/api/v1/query', params={
                'query': 'timestamp(guided_security_decisions_total{hands_on="H18"})'})
            response.raise_for_status()
            rows = response.json().get('data', {}).get('result', [])
            if (len(rows) == 2 and {r['metric'].get('decision') for r in rows} == {'allow', 'block'}
                    and all(float(r['value'][1]) * 1e9 >= after_ns for r in rows)):
                return
            if time.monotonic() >= deadline:
                raise TimeoutError('current Counter scrape missing')
            time.sleep(0.25)
    finally:
        if owned:
            client.close()


def collected_queries(queries, cases, start_ns, *, timeout=15):
    """Retry read-only learner queries while export is pending, never the actions."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            results = [execute_queries(queries, c['request_id'], c['trace_id'], start_ns, time.time_ns())
                       for c in cases]
            if all(r['products']['loki']['response'].get('data', {}).get('result')
                   and r['products']['tempo']['response'].get('batches',
                       r['products']['tempo']['response'].get('resourceSpans')) for r in results):
                return results
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError('current Log or Trace unavailable')
        time.sleep(0.25)


class NoticeStore:
    def __init__(self):
        self.calls = []

    def lookup(self, request_id, trace_id):
        result = {"notice_id": "training-notice", "text": "교육용 공지입니다."}
        self.calls.append({"request_id": request_id, "trace_id": trace_id,
                           "operation": "notice_lookup", "result": result})
        return result


def handle_action(action, principal, tracer, logger, counter, store):
    request_id = str(uuid.uuid4())
    started_ns = time.time_ns()
    with tracer.start_as_current_span("security.request", attributes={
        "hands_on": "H18", "request_id": request_id, "fixture": "notice-authorization",
    }) as root:
        trace_id = f"{root.get_span_context().trace_id:032x}"
        with tracer.start_as_current_span("authorize", attributes={"request_id": request_id}) as authorization:
            allowed = principal == "reader" and action == "notice_lookup"
            decision = "allow" if allowed else "block"
            authorization.set_attribute("decision", decision)
        result = None
        if allowed:
            with tracer.start_as_current_span("notice_lookup", attributes={"request_id": request_id}):
                result = store.lookup(request_id, trace_id)
        root.set_attribute("decision", decision)
        counter.labels("H18", decision).inc()
        logger.info("security_decision", extra={
            "hands_on": "H18", "request_id": request_id, "trace_id": trace_id,
            "decision": decision, "policy_rule": "notice-read-only", "fixture": "notice-authorization",
        })
    return {"request_id": request_id, "trace_id": trace_id, "decision": decision,
            "started_ns": started_ns, "finished_ns": time.time_ns(), "closed": True,
            "outcome": "completed" if allowed else "denied", "result": result,
            "policy_rule": "notice-read-only", "downstream_called": result is not None}


def run_suite(body, query_path, tracer, logger, counter, trace_provider, log_provider, state):
    suite_id = str(uuid.UUID(body["suite_id"]))
    if suite_id != body["suite_id"] or not isinstance(body["started_at"], str):
        raise ValueError("invalid suite metadata")
    ledger_path = state / f"H18-{suite_id}-ledger.json"
    # Exclusive creation prevents repeated suite IDs from replaying actions.
    with ledger_path.open("x", encoding="utf-8") as stream:
        json.dump({"suite_id": suite_id, "closed": False}, stream)
    wait_for_scrape(time.time_ns())
    store = NoticeStore()
    start_ns = time.time_ns()
    cases = [handle_action(action, "reader", tracer, logger, counter, store)
             for action in ("notice_lookup", "notice_publish")]
    ledger = {"suite_id": suite_id, "started_at": body["started_at"], "closed": True,
              "cases": cases, "downstream_calls": store.calls, "provider_mode": "synthetic-notice-store"}
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    trace_provider.force_flush()
    log_provider.force_flush()
    risk = cases[1]
    receipt = {"suite_id": suite_id, "started_at": body["started_at"], "activity": "H18",
               "activity_id": "P18", "contract_version": 2,
               "observed_at": datetime.now(timezone.utc).isoformat(),
               "request_id": risk["request_id"], "trace_id": risk["trace_id"],
               "decision": risk["decision"], "policy_rule": risk["policy_rule"],
               "main_called": False, "provider_mode": "synthetic-notice-store", "cases": cases,
               "source_digest": hashlib.sha256(query_path.read_bytes()).hexdigest()}
    try:
        queries = yaml.safe_load(query_path.read_text())
        receipt["queries"] = queries
        wait_for_scrape(cases[-1]['finished_ns'])
        receipt["query_executions"] = collected_queries(queries, cases, start_ns)
        receipt["query_execution"] = receipt["query_executions"][1]
    except (ValueError, yaml.YAMLError, httpx.HTTPError, TimeoutError):
        receipt["query_error"] = "learner query or product request failed"
    return receipt
