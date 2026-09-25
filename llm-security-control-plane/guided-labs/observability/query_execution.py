"""Execute learner queries against server-owned read-only product endpoints.

This module records product responses, not a completion or security verdict.
"""

import re
import uuid

import httpx


def execute_queries(queries, request_id, trace_id, start_ns, end_ns, *, client=None,
                    loki_url="http://loki:3100", tempo_url="http://tempo:3200",
                    prometheus_url="http://prometheus:9090"):
    if not isinstance(queries, dict) or set(queries) != {"logql", "promql", "trace_lookup"}:
        raise ValueError("query fields must be logql, promql and trace_lookup")
    if queries["trace_lookup"] != "exact_trace_id":
        raise ValueError("trace lookup must use the current exact trace ID")
    for key in ("logql", "promql"):
        if not isinstance(queries[key], str) or not queries[key].strip() or len(queries[key]) > 4096:
            raise ValueError(f"invalid {key}")
    if str(uuid.UUID(request_id)) != request_id or not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        raise ValueError("invalid execution identifiers")
    if type(start_ns) is not int or type(end_ns) is not int or not 0 < start_ns < end_ns <= start_ns + 60_000_000_000:
        raise ValueError("query window must be positive and at most 60 seconds")
    rendered = {key: queries[key].replace("{request_id}", request_id).replace("{trace_id}", trace_id)
                for key in ("logql", "promql")}
    requests = {
        "loki": (f"{loki_url}/loki/api/v1/query_range", {
            "query": rendered["logql"], "start": start_ns, "end": end_ns, "limit": 200}),
        "tempo": (f"{tempo_url}/api/traces/{trace_id}", {}),
        "prometheus": (f"{prometheus_url}/api/v1/query", {
            "query": rendered["promql"], "time": end_ns / 1_000_000_000}),
    }
    owned = client is None
    client = client or httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False)
    results = {}
    try:
        for product, (url, parameters) in requests.items():
            response = client.get(url, params=parameters, timeout=5.0)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError(f"invalid {product} response")
            if product != "tempo" and payload.get("status") != "success":
                raise ValueError(f"{product} query did not succeed")
            results[product] = {"parameters": parameters, "http_status": response.status_code, "response": payload}
    finally:
        if owned:
            client.close()
    return {"start_ns": start_ns, "end_ns": end_ns, "products": results}
