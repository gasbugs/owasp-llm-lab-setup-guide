"""Semantic P18 evidence checks. No golden learner source or query hashes."""

import base64
import json
import math


class EvidenceMismatch(ValueError):
    """Only verifier-authored requirements, never upstream error text."""


def require(condition, message):
    if not condition:
        raise EvidenceMismatch(message)


def check_ledger(receipt, ledger):
    require(receipt.get("activity_id") == "P18" and receipt.get("contract_version") == 2,
            "P18 contract version mismatch")
    require(ledger.get("closed") is True and ledger.get("suite_id") == receipt["suite_id"]
            and ledger.get("started_at") == receipt["started_at"], "execution ledger is not closed or current")
    cases = ledger.get("cases", [])
    require(len(cases) == 2 and cases == receipt.get("cases"), "case ledger mismatch")
    require([c.get("decision") for c in cases] == ["allow", "block"], "normal and denied cases required")
    require(len({c["request_id"] for c in cases}) == 2 and len({c["trace_id"] for c in cases}) == 2,
            "request and trace IDs must be distinct")
    require(all(c.get("closed") is True for c in cases), "open case")
    calls = ledger.get("downstream_calls", [])
    require(len(calls) == 1 and calls[0].get("operation") == "notice_lookup"
            and calls[0].get("request_id") == cases[0]["request_id"]
            and calls[0].get("trace_id") == cases[0]["trace_id"]
            and calls[0].get("result") == cases[0].get("result")
            and cases[0].get("result", {}).get("notice_id") == "training-notice",
            "normal downstream result missing or wrong")
    require(cases[0].get("downstream_called") is True and cases[1].get("downstream_called") is False
            and cases[1].get("result") is None, "denied request reached downstream")
    return cases


def check_logs(payload, case):
    require(payload.get("status") == "success", "Loki query failed")
    data = payload.get("data", {})
    require(data.get("resultType") == "streams", "LogQL must return log streams")
    count = 0
    for stream in data.get("result", []):
        for row in stream.get("values", []):
            attributes = dict(stream.get("stream", {}))
            if len(row) > 2:
                attributes.update(row[2])
            try:
                body = json.loads(row[1])
            except (ValueError, TypeError):
                body = {}
            if isinstance(body, dict):
                for key, value in body.items():
                    require(key not in attributes or attributes[key] == value, "conflicting log attributes")
                    attributes[key] = value
            require(attributes.get("service_name") == "guided-h18-queries", "foreign service log")
            for key in ("request_id", "trace_id", "decision"):
                require(attributes.get(key) == case[key], f"log {key} differs from this request")
            require(attributes.get("policy_rule") == "notice-read-only", "wrong log policy")
            require(case["started_ns"] <= int(row[0]) <= case["finished_ns"], "log outside request interval")
            count += 1
    require(count > 0, "no current request log returned")
    return count


def attributes(span):
    return {item["key"]: item.get("value", {}).get("stringValue") for item in span.get("attributes", [])}


def identifier(value, size):
    if isinstance(value, str) and len(value) == size * 2:
        try:
            return bytes.fromhex(value).hex()
        except ValueError:
            pass
    decoded = base64.b64decode(value, validate=True)
    require(len(decoded) == size, 'incorrect Trace identifier length')
    return decoded.hex()


def check_trace(payload, case):
    spans = []
    for resource in payload.get("batches", payload.get("resourceSpans", [])):
        for scope in resource.get("scopeSpans", resource.get("instrumentationLibrarySpans", [])):
            spans.extend(scope.get("spans", []))
    names = [s.get("name") for s in spans]
    expected = ["security.request", "authorize"] + (["notice_lookup"] if case["decision"] == "allow" else [])
    require(sorted(names) == sorted(expected), "Trace stages do not match the actual decision")
    roots = [s for s in spans if s["name"] == "security.request"]
    root = roots[0]
    root_id = identifier(root["spanId"], 8)
    require(not root.get("parentSpanId"), "request span must be a root")
    for span in spans:
        require(identifier(span["traceId"], 16) == case["trace_id"], "foreign trace")
        attrs = attributes(span)
        require(attrs.get("request_id") == case["request_id"], "foreign request span")
        if span["name"] in {"security.request", "authorize"}:
            require(attrs.get("decision") == case["decision"], "Trace decision mismatch")
        if span is not root:
            require(identifier(span.get("parentSpanId"), 8) == root_id, "broken parent span link")
    return names


def counter_values(payload):
    require(payload.get("status") == "success" and payload.get("data", {}).get("resultType") == "vector",
            "PromQL must return a vector grouped by decision")
    values = {}
    for row in payload["data"].get("result", []):
        metric = row.get("metric", {})
        decision = metric.get("decision")
        require(decision in {"allow", "block"} and decision not in values, "unexpected or duplicate decision series")
        require(metric.get("hands_on", "H18") == "H18", "foreign metric activity")
        value = float(row["value"][1])
        require(math.isfinite(value) and value >= 0, "invalid Counter value")
        values[decision] = value
    require(set(values) == {"allow", "block"}, "normal and denied Counter series required")
    return values


def check_counter_change(before, after):
    old, new = counter_values(before), counter_values(after)
    require(all(new[key] - old[key] == 1 for key in old), "Counter must increase once for each decision")
    return {key: new[key] - old[key] for key in old}
