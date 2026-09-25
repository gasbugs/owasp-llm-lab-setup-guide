"""Actual SQLite FTS and local identity boundaries, ASGI transport; no vector/LLM/AWS."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-protected-services"
sys.path.insert(0, str(ROOT))
from context_store import ContextStore, ContextError
from context_server import create_app

TOKENS = {role: "context-test-" + role for role in ("control", "service", "verifier")}
DOCS = [{"document_id": "account", "tenant": "team-a", "text": "계정 복구 안내: 지원 담당자에게 문의하세요."},
        {"document_id": "delivery", "tenant": "team-a", "text": "배송 안내: 운송장으로 확인하세요."},
        {"document_id": "foreign", "tenant": "team-b", "text": "계정 복구: 다른 팀의 합성 문서."}]


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "context.sqlite3"
        self.now = [1000.0]
        self.store = ContextStore(self.path, "a" * 64, now=lambda: self.now[0])
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.registration = self.store.register(self.suite, [self.execution], DOCS)

    def execute(self, stage, value):
        return self.store.execute(self.suite, self.execution, stage, value)

    def authenticate(self, role="reader"):
        return self.execute("authenticate", self.registration["credentials"][role])

    def authorize(self, tenant="team-a"):
        return self.execute("authorize", tenant)

    def test_normal_search_actual_content_and_closed_count(self):
        self.assertTrue(self.authenticate()["allowed"])
        self.assertTrue(self.authorize()["allowed"])
        result = self.execute("retrieval", "계정 복구")
        self.assertEqual(result["text"], DOCS[0]["text"])
        self.assertEqual([hit["document_id"] for hit in result["evidence"]["hits"]], ["account"])
        self.assertIsNone(self.store.ledger(self.suite)["retrieval_count"])
        self.store.close(self.suite)
        ledger = self.store.ledger(self.suite)
        self.assertEqual(ledger["retrieval_count"], 1)
        self.assertEqual([row["stage"] for row in ledger["calls"]], ["authenticate", "authorize", "retrieval"])
        self.assertNotIn("계정", json.dumps(ledger))
        for token in self.registration["credentials"].values():
            self.assertNotIn(token, json.dumps(ledger))
            self.assertNotIn(token.encode(), self.path.read_bytes())
        self.assertNotIn("task_completed", ledger)

    def test_query_changes_results_not_case_id(self):
        self.authenticate()
        self.authorize()
        self.assertEqual(self.execute("retrieval", "배송")["text"], DOCS[1]["text"])

    def test_invalid_credential_cannot_authorize_or_search(self):
        self.assertFalse(self.execute("authenticate", "wrong-fixture-credential")["allowed"])
        self.assertFalse(self.authorize()["allowed"])
        with self.assertRaises(ContextError) as error:
            self.execute("retrieval", "계정")
        self.assertEqual(error.exception.status, 403)
        self.store.close(self.suite)
        self.assertEqual(self.store.ledger(self.suite)["retrieval_count"], 0)

    def test_authenticated_visitor_has_no_read_scope(self):
        self.assertTrue(self.authenticate("visitor")["allowed"])
        self.assertFalse(self.authorize()["allowed"])
        with self.assertRaises(ContextError):
            self.execute("retrieval", "계정")

    def test_cross_tenant_authorization_denied(self):
        self.authenticate()
        self.assertFalse(self.authorize("team-b")["allowed"])
        with self.assertRaises(ContextError):
            self.execute("retrieval", "계정")

    def test_search_before_authentication_does_not_query(self):
        with self.assertRaises(ContextError):
            self.execute("retrieval", "계정")
        self.store.close(self.suite)
        ledger = self.store.ledger(self.suite)
        self.assertEqual(ledger["retrieval_count"], 0)
        self.assertEqual(ledger["calls"][0]["state"], "rejected")

    def test_other_suite_documents_and_credentials_are_not_visible(self):
        other = str(uuid4())
        issued = self.store.register(other, [self.execution], [{"document_id": "other", "tenant": "team-a", "text": "계정 복구 다른 실행 문서"}])
        self.assertFalse(self.execute("authenticate", issued["credentials"]["reader"])["allowed"])
        self.store.execute(other, self.execution, "authenticate", issued["credentials"]["reader"])
        self.store.execute(other, self.execution, "authorize", "team-a")
        response = self.store.execute(other, self.execution, "retrieval", "계정 복구")
        self.assertEqual([row["document_id"] for row in response["evidence"]["hits"]], ["other"])

    def test_query_syntax_cannot_remove_scope_filter(self):
        self.authenticate()
        self.authorize()
        response = self.execute("retrieval", '계정 OR tenant:team-b " *')
        self.assertTrue(response["evidence"]["hits"])
        self.assertTrue(all(row["tenant"] == "team-a" for row in response["evidence"]["hits"]))

    def test_empty_results_remain_a_completed_actual_query(self):
        self.authenticate()
        self.authorize()
        response = self.execute("retrieval", "nomatchingfixtureword")
        self.assertEqual(response["text"], "")
        self.assertEqual(response["evidence"]["hits"], [])
        self.store.close(self.suite)
        self.assertEqual(self.store.ledger(self.suite)["retrieval_count"], 1)

    def test_concurrent_duplicate_only_runs_once(self):
        def run(_):
            try:
                return self.authenticate()["allowed"]
            except ContextError as error:
                return error.status
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(run, range(8)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(409), 7)
        self.assertEqual(len(self.store.ledger(self.suite)["calls"]), 1)

    def test_close_restart_and_source_mismatch(self):
        self.authenticate()
        changed = ContextStore(self.path, "b" * 64, now=lambda: self.now[0])
        with self.assertRaises(ContextError) as error:
            changed.execute(self.suite, self.execution, "authorize", "team-a")
        self.assertEqual(error.exception.status, 409)
        self.store.close(self.suite)
        before = self.store.ledger(self.suite)
        self.now[0] += 1
        self.assertEqual(changed.close(self.suite)["closed_at"], before["closed_at"])
        self.assertEqual(changed.ledger(self.suite), before)

    def test_failure_keeps_retrieval_count_unknown(self):
        self.authenticate()
        self.authorize()
        with patch.object(self.store, "_perform", side_effect=RuntimeError("private error text")):
            with self.assertRaises(ContextError) as error:
                self.execute("retrieval", "계정")
        self.assertEqual(str(error.exception), "context processing failed")
        self.store.close(self.suite)
        self.assertIsNone(self.store.ledger(self.suite)["retrieval_count"])

    def test_interrupted_processing_retains_pending_across_restart(self):
        self.authenticate()
        self.authorize()
        with patch.object(self.store, "_perform", side_effect=SystemExit("simulated process interruption")):
            with self.assertRaises(SystemExit):
                self.execute("retrieval", "계정")
        restarted = ContextStore(self.path, "a" * 64, now=lambda: self.now[0])
        ledger = restarted.ledger(self.suite)
        self.assertEqual(ledger["calls"][-1]["state"], "pending")
        self.assertIsNone(ledger["retrieval_count"])
        with self.assertRaises(ContextError) as error:
            restarted.close(self.suite)
        self.assertEqual(error.exception.status, 409)

    def test_expiry_unknown_execution_and_closed_suite(self):
        with self.assertRaises(ContextError) as error:
            self.store.execute(self.suite, str(uuid4()), "authenticate", "unknown")
        self.assertEqual(error.exception.status, 404)
        self.now[0] += 180
        with self.assertRaises(ContextError) as error:
            self.authenticate()
        self.assertEqual(error.exception.status, 409)
        self.store.close(self.suite)
        self.now[0] = 1000
        with self.assertRaises(ContextError):
            self.authenticate()

    def test_bad_registration_does_not_create_partial_suite(self):
        for documents in ([], DOCS * 2, [{**DOCS[0], "approved": True}], [{**DOCS[0], "text": " "}]):
            suite = str(uuid4())
            with self.assertRaises(ContextError):
                self.store.register(suite, [self.execution], documents)
            with self.assertRaises(ContextError):
                self.store.ledger(suite)

    def test_http_roles_field_validation_and_native_search(self):
        client = TestClient(create_app(database=Path(self.temp.name) / "http.sqlite3", tokens=TOKENS))
        headers = lambda role: {"Authorization": "Bearer " + TOKENS[role]}
        body = {"suite_id": self.suite, "execution_ids": [self.execution], "documents": DOCS}
        for role in ("service", "verifier"):
            self.assertEqual(client.post("/v1/suites", headers=headers(role), json=body).status_code, 401)
        result = client.post("/v1/suites", headers=headers("control"), json=body)
        self.assertEqual(result.status_code, 200)
        base = {"suite_id": self.suite, "execution_id": self.execution}
        for extra in ({"subject": "reader"}, {"role": "reader"}, {"task_completed": True}):
            response = client.post("/v1/stages/authenticate", headers=headers("service"),
                                   json={**base, "value": "private-token", **extra})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("private-token", response.text)
        for stage, value in (("authenticate", result.json()["credentials"]["reader"]), ("authorize", "team-a"), ("retrieval", "계정")):
            response = client.post("/v1/stages/" + stage, headers=headers("service"), json={**base, "value": value})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["text"], DOCS[0]["text"])
        self.assertEqual(client.get(f"/v1/suites/{self.suite}/ledger", headers=headers("service")).status_code, 401)
        self.assertEqual(client.get("/v1/build-info", headers=headers("control")).status_code, 401)
        self.assertEqual(client.post(f"/v1/suites/{self.suite}/close", headers=headers("control"), json={}).status_code, 200)
        ledger = client.get(f"/v1/suites/{self.suite}/ledger", headers=headers("verifier")).json()
        build = client.get("/v1/build-info", headers=headers("verifier")).json()
        self.assertEqual(ledger["service_digest"], build["source_digest"])
        self.assertEqual(ledger["retrieval_count"], 1)


if __name__ == "__main__":
    unittest.main()
