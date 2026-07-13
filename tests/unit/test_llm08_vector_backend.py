"""Deterministic contracts for the LLM08 educational vector backend."""
from __future__ import annotations

import asyncio
import importlib
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
VULN_RAG_ROOT = ROOT / "docker" / "vuln-rag"


def load_day4_module():
    """Load vuln-rag's generic ``app`` package without leaking it to other tests."""
    saved_app_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == "app" or name.startswith("app.")
    }
    for name in saved_app_modules:
        del sys.modules[name]

    sys.path.insert(0, str(VULN_RAG_ROOT))
    try:
        return importlib.import_module("app.scenarios.day4")
    finally:
        sys.path.remove(str(VULN_RAG_ROOT))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                del sys.modules[name]
        sys.modules.update(saved_app_modules)


DAY4 = load_day4_module()


def load_embedding_module():
    """Load EmbeddingClient against a dependency-free fake httpx transport."""
    fake_httpx = ModuleType("httpx")

    class HTTPError(Exception):
        pass

    class Timeout:
        def __init__(self, seconds):
            self.seconds = seconds

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    class AsyncClient:
        payload = {"embeddings": [[1.0, 0.0]]}
        calls = []

        def __init__(self, *, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def post(self, url, *, json):
            self.__class__.calls.append({"url": url, "json": json})
            return FakeResponse(self.__class__.payload)

    fake_httpx.HTTPError = HTTPError
    fake_httpx.Timeout = Timeout
    fake_httpx.AsyncClient = AsyncClient

    previous = sys.modules.get("httpx")
    sys.modules["httpx"] = fake_httpx
    try:
        spec = importlib.util.spec_from_file_location(
            "llm08_embedding_under_test", VULN_RAG_ROOT / "app" / "embedding.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            del sys.modules["httpx"]
        else:
            sys.modules["httpx"] = previous
    return module, AsyncClient


EMBEDDING, FakeAsyncClient = load_embedding_module()


class FakeEmbeddingBackend:
    model = "bge-m3:test-fixture"

    async def embed(self, inputs):
        def vector(text: str) -> list[float]:
            if "Phoenix project" in text:
                return [1.0, 0.0]
            if "API key" in text:
                return [0.8, 0.2]
            if "passcode" in text:
                return [0.1, 0.9]
            if "revenue" in text:
                return [0.0, 1.0]
            return [0.5, 0.5]

        return [vector(text) for text in inputs]


class Llm08VectorBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeEmbeddingBackend()
        self.principal = DAY4.authenticate_tenant(
            "Bearer llm08-acme-demo-token"
        )
        self.query = "Beta team plans to launch Phoenix project on 2026-07-01."
        FakeAsyncClient.calls = []
        FakeAsyncClient.payload = {
            "model": "bge-m3:test-fixture",
            "embeddings": [[1.0, 0.0]],
        }

    def search(self, mode: str) -> dict:
        return asyncio.run(
            DAY4.vector_search(
                query=self.query,
                principal=self.principal,
                mode=mode,
                top_k=2,
                embedding_backend=self.backend,
            )
        )

    def test_bearer_token_resolves_server_side_tenant(self) -> None:
        self.assertEqual(self.principal.subject, "llm08-acme-observer")
        self.assertEqual(self.principal.tenant, "acme")
        for invalid in (None, "", "Basic abc", "Bearer client-supplied-acme"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(DAY4.TenantAuthenticationError):
                    DAY4.authenticate_tenant(invalid)

    def test_embedding_client_batches_inputs_through_ollama_api(self) -> None:
        FakeAsyncClient.calls = []
        FakeAsyncClient.payload = {
            "model": "bge-m3:test-fixture",
            "embeddings": [[1.0, 0.0], [0.0, 1.0]],
        }
        client = EMBEDDING.EmbeddingClient(
            base_url="http://lab-ollama:11434/",
            model="bge-m3:test-fixture",
        )

        vectors = asyncio.run(client.embed(["first", "second"]))

        self.assertEqual(vectors, [[1.0, 0.0], [0.0, 1.0]])
        self.assertEqual(
            FakeAsyncClient.calls,
            [
                {
                    "url": "http://lab-ollama:11434/api/embed",
                    "json": {
                        "model": "bge-m3:test-fixture",
                        "input": ["first", "second"],
                    },
                }
            ],
        )

    def test_embedding_client_rejects_malformed_batch(self) -> None:
        FakeAsyncClient.payload = {
            "model": "bge-m3:test-fixture",
            "embeddings": [[1.0, 0.0]],
        }
        client = EMBEDDING.EmbeddingClient(model="bge-m3:test-fixture")

        with self.assertRaises(EMBEDDING.EmbeddingBackendError):
            asyncio.run(client.embed(["first", "second"]))

    def test_embedding_client_rejects_model_mismatch(self) -> None:
        FakeAsyncClient.payload = {
            "model": "unexpected-model:latest",
            "embeddings": [[1.0, 0.0]],
        }
        client = EMBEDDING.EmbeddingClient(model="bge-m3:test-fixture")

        with self.assertRaisesRegex(
            EMBEDDING.EmbeddingBackendError,
            "unexpected model",
        ):
            asyncio.run(client.embed(["first"]))

    def test_vulnerable_search_scores_all_tenants_without_filter(self) -> None:
        result = self.search("vulnerable")

        self.assertEqual(result["engine"], "educational-in-memory-cosine")
        self.assertEqual(
            result["engine_label"],
            "교육용 인메모리 cosine 검색기",
        )
        self.assertEqual(result["model"], self.backend.model)
        self.assertEqual(result["dimensions"], 2)
        self.assertEqual(result["candidate_count"], 4)
        self.assertEqual(
            result["filter"],
            {"field": "tenant", "applied": False, "value": None},
        )
        self.assertEqual(result["hits"][0]["document_id"], "beta/launch.md")
        self.assertEqual(result["hits"][0]["tenant"], "beta")
        self.assertEqual([hit["rank"] for hit in result["hits"]], [1, 2])
        self.assertGreaterEqual(result["hits"][0]["score"], result["hits"][1]["score"])
        self.assertEqual(
            set(result["hits"][0]),
            {"document_id", "tenant", "rank", "score", "text"},
        )

    def test_safe_search_filters_metadata_before_vector_scoring(self) -> None:
        result = self.search("safe")

        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(
            result["filter"],
            {"field": "tenant", "applied": True, "value": "acme"},
        )
        self.assertEqual({hit["tenant"] for hit in result["hits"]}, {"acme"})
        self.assertNotIn("beta", " ".join(result["retrieved_chunks"]))

    def test_hidden_target_endpoint_payload_omits_owner_plaintext(self) -> None:
        result = asyncio.run(DAY4.target_vector(self.backend))

        self.assertEqual(
            set(result),
            {"fixture_id", "model", "dimensions", "embedding"},
        )
        self.assertEqual(result["fixture_id"], "llm08-owner-vector-v1")
        self.assertEqual(result["dimensions"], len(result["embedding"]))
        self.assertNotIn(DAY4._LLM08_TARGET_PLAINTEXT, json.dumps(result))

    def test_cosine_rejects_invalid_vectors(self) -> None:
        self.assertAlmostEqual(DAY4.cosine_similarity([1.0, 0.0], [1.0, 0.0]), 1.0)
        for left, right in (([], []), ([1.0], [1.0, 2.0]), ([0.0], [1.0])):
            with self.subTest(left=left, right=right):
                with self.assertRaises(ValueError):
                    DAY4.cosine_similarity(left, right)

    def test_api_routes_are_paired_and_legacy_chat_stays_keyword_based(self) -> None:
        source = (VULN_RAG_ROOT / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn('@app.post("/api/labs/llm08/vulnerable/search")', source)
        self.assertIn('@app.post("/api/labs/llm08/safe/search")', source)
        self.assertIn('@app.post("/api/labs/llm08/vulnerable/chat")', source)
        self.assertIn('@app.post("/api/labs/llm08/safe/chat")', source)
        self.assertIn('@app.post("/api/embed")', source)
        self.assertIn('@app.get("/api/lab/llm08/target-vector")', source)
        self.assertIn('model_config = ConfigDict(extra="forbid")', source)
        self.assertIn('request.headers.get("authorization")', source)
        self.assertIn(
            'context=search_evidence["retrieved_chunks"]',
            source,
        )
        self.assertIn(
            "reply = await llm.chat(system=system_prompt, user=request_body.query)",
            source,
        )
        self.assertIn('"vector_search": search_evidence', source)

        legacy_chat = source.split('@app.post("/api/chat")', 1)[1].split(
            '@app.post("/api/admin/inject-doc")', 1
        )[0]
        self.assertIn("context = selected.retrieve(req.message)", legacy_chat)
        self.assertNotIn("vector_search", legacy_chat)

    def test_ollama_batch_embedding_and_installer_contract(self) -> None:
        embedding_source = (VULN_RAG_ROOT / "app" / "embedding.py").read_text(
            encoding="utf-8"
        )
        installer = (
            ROOT / "infrastructure" / "scripts" / "student" / "install-lab.sh"
        ).read_text(encoding="utf-8")
        dockerfile = (VULN_RAG_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn('f"{self.base_url}/api/embed"', embedding_source)
        self.assertIn('json={"model": self.model, "input": texts}', embedding_source)
        self.assertIn('OLLAMA_EMBED_MODEL="${OLLAMA_EMBED_MODEL:-bge-m3:latest}"', installer)
        self.assertIn("Environment=OLLAMA_EMBED_MODEL=$OLLAMA_EMBED_MODEL", installer)
        self.assertIn('ollama pull "$OLLAMA_EMBED_MODEL"', installer)
        self.assertIn("http://localhost:11434/api/embed", installer)
        self.assertIn("http://localhost:8012/api/embed", installer)
        self.assertIn("LLM08 embed capability ready", installer)
        self.assertNotIn("sentence-transformers", installer)
        self.assertIn("python3-venv", installer)
        self.assertIn("/home/ubuntu/work/llm08-analysis-venv", installer)
        self.assertIn("pip install --no-cache-dir -q numpy", installer)
        self.assertIn("OLLAMA_EMBED_MODEL=bge-m3:latest", dockerfile)

    def test_cleanup_stops_only_verified_llm08_mini_app_pid(self) -> None:
        cleanup = (
            ROOT / "infrastructure" / "scripts" / "student" / "cleanup-lab.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("stop_llm08_mini_app", cleanup)
        self.assertIn("/home/ubuntu/work/llm08-mini-app/server.pid", cleanup)
        self.assertIn("/home/ubuntu/work/llm08-mini-app/mini-app.pid", cleanup)
        self.assertIn("/proc/$pid/cmdline", cleanup)
        self.assertIn('"--port 18080"', cleanup)
        self.assertIn("refusing to stop unexpected process", cleanup)
        self.assertIn("including LLM08 source/evidence", cleanup)


if __name__ == "__main__":
    unittest.main()
