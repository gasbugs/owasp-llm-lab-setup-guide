"""P18 query transport contract; product responses are explicit fixtures."""

import importlib.util
from pathlib import Path
import unittest

import httpx

PATH = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/observability/query_execution.py"
spec = importlib.util.spec_from_file_location("p18_query_execution", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class QueryExecutionTests(unittest.TestCase):
    def setUp(self):
        self.queries = {"logql": '{service_name="guided-observability"} |= "{request_id}"',
                        "promql": 'sum(guided_security_decisions_total{hands_on="H18"})',
                        "trace_lookup": "exact_trace_id"}
        self.request_id = "11111111-1111-4111-8111-111111111111"
        self.trace_id = "a" * 32
        self.calls = []

    def handler(self, request):
        self.calls.append(request)
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})

    def run_query(self, queries=None, handler=None, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(handler or self.handler)) as client:
            return module.execute_queries(self.queries if queries is None else queries,
                                          self.request_id, self.trace_id, 1_000_000_000,
                                          kwargs.pop("end_ns", 3_000_000_000), client=client, **kwargs)

    def test_actual_learner_strings_are_sent_with_fixed_destinations_and_window(self):
        result = self.run_query()
        self.assertEqual([r.url.host for r in self.calls], ["loki", "tempo", "prometheus"])
        self.assertEqual(self.calls[0].url.params["query"], self.queries["logql"].replace("{request_id}", self.request_id))
        self.assertEqual(self.calls[2].url.params["query"], self.queries["promql"])
        self.assertEqual(self.calls[0].url.params["limit"], "200")
        self.assertEqual(self.calls[0].url.params["start"], "1000000000")
        self.assertEqual(self.calls[2].url.params["time"], "3.0")
        self.assertEqual(self.calls[1].url.path, f"/api/traces/{self.trace_id}")
        self.assertEqual(result["products"]["loki"]["response"]["data"]["result"], [])
        self.assertNotIn("task_completed", result)

    def test_alternate_query_is_not_replaced_by_a_golden_query(self):
        alternate = {**self.queries, "promql": 'sum by (decision) (guided_security_decisions_total{hands_on="H18"})'}
        self.run_query(alternate)
        self.assertEqual(self.calls[2].url.params["query"], alternate["promql"])

    def test_invalid_schema_or_unbounded_query_makes_no_request(self):
        for queries in ({}, {**self.queries, "url": "http://other"},
                        {**self.queries, "trace_lookup": "latest"},
                        {**self.queries, "logql": " "}, {**self.queries, "promql": "x" * 4097}):
            with self.subTest(queries=str(queries)[:80]), self.assertRaises(ValueError):
                self.run_query(queries)
        self.assertEqual(self.calls, [])

    def test_invalid_window_makes_no_request(self):
        for end in (0, 1_000_000_000, 61_000_000_001, True):
            with self.subTest(end=end), self.assertRaises(ValueError):
                self.run_query(end_ns=end)
        self.assertEqual(self.calls, [])

    def test_product_syntax_error_is_not_success(self):
        with self.assertRaises(httpx.HTTPStatusError):
            self.run_query(handler=lambda request: httpx.Response(400, json={"error": "syntax"}))

    def test_http_200_error_payload_is_not_success(self):
        with self.assertRaises(ValueError):
            self.run_query(handler=lambda request: httpx.Response(200, json={"status": "error"}))

    def test_malformed_json_is_not_success(self):
        with self.assertRaises(ValueError):
            self.run_query(handler=lambda request: httpx.Response(200, text="not-json"))

    def test_redirect_is_not_followed(self):
        with self.assertRaises(httpx.HTTPStatusError):
            self.run_query(handler=lambda request: httpx.Response(302, headers={"Location": "http://elsewhere"}))

    def test_identifier_cannot_change_trace_path(self):
        self.trace_id = "../other"
        with self.assertRaises(ValueError):
            self.run_query()
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
