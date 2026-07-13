"""ASGI integration contracts for the LLM08 paired vector routes."""
from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
VULN_RAG_ROOT = ROOT / "docker" / "vuln-rag"


def load_main_module():
    """Load vuln-rag's ASGI app without leaking its generic app package."""
    saved_app_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == "app" or name.startswith("app.")
    }
    for name in saved_app_modules:
        del sys.modules[name]

    sys.path.insert(0, str(VULN_RAG_ROOT))
    previous_default_scenario = os.environ.get("DEFAULT_SCENARIO")
    os.environ["DEFAULT_SCENARIO"] = "day4"
    try:
        return importlib.import_module("app.main")
    finally:
        if previous_default_scenario is None:
            del os.environ["DEFAULT_SCENARIO"]
        else:
            os.environ["DEFAULT_SCENARIO"] = previous_default_scenario
        sys.path.remove(str(VULN_RAG_ROOT))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                del sys.modules[name]
        sys.modules.update(saved_app_modules)


MAIN = load_main_module()


class FakeEmbeddingBackend:
    model = "bge-m3:asgi-fixture"

    async def embed(self, inputs):
        def vector(text: str) -> list[float]:
            if text == "Phoenix status":
                return [1.0, 0.0]
            if "Phoenix project" in text:
                return [1.0, 0.0]
            if "API key" in text:
                return [0.8, 0.2]
            if "passcode" in text:
                return [0.1, 0.9]
            if "revenue" in text:
                return [0.0, 1.0]
            if "owner approval" in text:
                return [0.9, 0.1]
            return [0.5, 0.5]

        return [vector(text) for text in inputs]


class FakeLLM:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    async def chat(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        return f"fixture reply: {user}"


class BrokenEmbeddingBackend:
    model = "bge-m3:broken-fixture"

    async def embed(self, inputs):
        raise MAIN.EmbeddingBackendError("fixture backend unavailable")


class Llm08VectorApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_embedding = MAIN.embedding
        self.original_llm = MAIN.llm
        self.embedding = FakeEmbeddingBackend()
        self.llm = FakeLLM()
        MAIN.embedding = self.embedding
        MAIN.llm = self.llm
        self.client = TestClient(MAIN.app)
        self.headers = {"Authorization": "Bearer llm08-acme-demo-token"}
        self.body = {"query": "Phoenix status", "top_k": 2}

    def tearDown(self) -> None:
        self.client.close()
        MAIN.embedding = self.original_embedding
        MAIN.llm = self.original_llm

    def test_auth_body_schema_and_embed_bounds(self) -> None:
        missing = self.client.post(
            "/api/labs/llm08/vulnerable/search",
            json=self.body,
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.headers["www-authenticate"], "Bearer")

        spoof = self.client.post(
            "/api/labs/llm08/safe/search",
            headers=self.headers,
            json={**self.body, "tenant": "beta"},
        )
        self.assertEqual(spoof.status_code, 422)

        too_long = self.client.post(
            "/api/embed",
            headers=self.headers,
            json={"input": "x" * 4097},
        )
        self.assertEqual(too_long.status_code, 422)
        self.assertIn("4096", too_long.json()["detail"])

        maximum = self.client.post(
            "/api/embed",
            headers=self.headers,
            json={"input": "x" * 4096},
        )
        self.assertEqual(maximum.status_code, 200)
        self.assertEqual(maximum.json()["input_count"], 1)

        too_many = self.client.post(
            "/api/embed",
            headers=self.headers,
            json={"input": ["x"] * 17},
        )
        self.assertEqual(too_many.status_code, 422)

    def test_llm08_routes_are_hidden_on_non_day4_services(self) -> None:
        previous_scenario = MAIN.DEFAULT_SCENARIO
        MAIN.DEFAULT_SCENARIO = "day2"
        try:
            requests = (
                ("post", "/api/labs/llm08/vulnerable/search", self.body),
                ("post", "/api/labs/llm08/safe/search", self.body),
                ("post", "/api/labs/llm08/vulnerable/chat", self.body),
                ("post", "/api/labs/llm08/safe/chat", self.body),
                ("post", "/api/embed", {"input": "candidate"}),
                ("get", "/api/lab/llm08/target-vector", None),
            )
            for method, path, body in requests:
                with self.subTest(path=path):
                    response = self.client.request(method, path, json=body)
                    self.assertEqual(response.status_code, 404)
        finally:
            MAIN.DEFAULT_SCENARIO = previous_scenario

    def test_paired_search_routes_apply_filter_before_scoring(self) -> None:
        vulnerable = self.client.post(
            "/api/labs/llm08/vulnerable/search",
            headers=self.headers,
            json=self.body,
        )
        safe = self.client.post(
            "/api/labs/llm08/safe/search",
            headers=self.headers,
            json=self.body,
        )

        self.assertEqual(vulnerable.status_code, 200)
        self.assertEqual(safe.status_code, 200)
        vulnerable_body = vulnerable.json()
        safe_body = safe.json()
        self.assertFalse(vulnerable_body["filter"]["applied"])
        self.assertEqual(vulnerable_body["candidate_count"], 4)
        self.assertEqual(vulnerable_body["hits"][0]["tenant"], "beta")
        self.assertEqual(vulnerable_body["hits"][0]["document_id"], "beta/launch.md")
        self.assertEqual(
            vulnerable_body["engine_label"],
            "교육용 인메모리 cosine 검색기",
        )

        self.assertEqual(
            safe_body["filter"],
            {"field": "tenant", "applied": True, "value": "acme"},
        )
        self.assertEqual(safe_body["candidate_count"], 2)
        self.assertEqual({hit["tenant"] for hit in safe_body["hits"]}, {"acme"})
        self.assertEqual(vulnerable_body["model"], safe_body["model"])
        self.assertEqual(vulnerable_body["dimensions"], safe_body["dimensions"])
        self.assertEqual(
            vulnerable_body["authenticated_context"],
            safe_body["authenticated_context"],
        )

    def test_paired_chat_routes_use_their_vector_context(self) -> None:
        vulnerable = self.client.post(
            "/api/labs/llm08/vulnerable/chat",
            headers=self.headers,
            json=self.body,
        )
        safe = self.client.post(
            "/api/labs/llm08/safe/chat",
            headers=self.headers,
            json=self.body,
        )

        self.assertEqual(vulnerable.status_code, 200)
        self.assertEqual(safe.status_code, 200)
        self.assertFalse(vulnerable.json()["vector_search"]["filter"]["applied"])
        self.assertTrue(safe.json()["vector_search"]["filter"]["applied"])
        self.assertEqual(len(self.llm.calls), 2)
        self.assertIn("[beta/launch.md]", self.llm.calls[0]["system"])
        self.assertNotIn("[beta/launch.md]", self.llm.calls[1]["system"])

    def test_target_vector_contract_and_backend_error_mapping(self) -> None:
        target = self.client.get(
            "/api/lab/llm08/target-vector",
            headers=self.headers,
        )
        self.assertEqual(target.status_code, 200)
        self.assertEqual(
            set(target.json()),
            {"fixture_id", "model", "dimensions", "embedding"},
        )

        MAIN.embedding = BrokenEmbeddingBackend()
        for method, path, body in (
            ("post", "/api/embed", {"input": "candidate"}),
            ("post", "/api/labs/llm08/safe/search", self.body),
            ("get", "/api/lab/llm08/target-vector", None),
        ):
            with self.subTest(path=path):
                response = self.client.request(
                    method,
                    path,
                    headers=self.headers,
                    json=body,
                )
                self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
