"""Focused, network-free tests for the learner-built LLM08 mini app."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP_PATH = ROOT / "examples" / "llm08" / "mini_vector_search_app.py"
SPEC = importlib.util.spec_from_file_location("llm08_mini_vector_search_app", APP_PATH)
APP = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = APP
SPEC.loader.exec_module(APP)


class FakeEmbed:
    model = "bge-m3:fake"

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, texts):
        values = list(texts)
        self.calls.append(values)

        def vector(text: str) -> list[float]:
            if text == "Phoenix status" or "Phoenix project" in text:
                return [1.0, 0.0]
            if "API key" in text:
                return [0.8, 0.2]
            if "passcode" in text:
                return [0.1, 0.9]
            if "revenue" in text:
                return [0.0, 1.0]
            return [0.5, 0.5]

        return self.model, [vector(text) for text in values]


class MiniVectorSearchAppTest(unittest.TestCase):
    def test_vulnerable_mode_ranks_all_tenants(self) -> None:
        fake = FakeEmbed()

        result = APP.semantic_search("Phoenix status", "vulnerable", 2, fake)

        self.assertEqual(result["engine"], "learner-mini-in-memory-cosine")
        self.assertEqual(result["model"], fake.model)
        self.assertEqual(result["dimensions"], 2)
        self.assertEqual(result["authenticated_tenant"], "acme")
        self.assertFalse(result["filter_applied"])
        self.assertEqual(result["candidate_count"], 4)
        self.assertEqual(result["hits"][0]["document_id"], "beta/launch.md")
        self.assertEqual(result["hits"][0]["tenant"], "beta")
        self.assertEqual(len(fake.calls[0]), 5)

    def test_safe_mode_prefilters_before_embedding_and_ranking(self) -> None:
        fake = FakeEmbed()

        result = APP.semantic_search("Phoenix status", "safe", 2, fake)

        self.assertTrue(result["filter_applied"])
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual({hit["tenant"] for hit in result["hits"]}, {"acme"})
        self.assertEqual(len(fake.calls[0]), 3)
        self.assertFalse(any("Beta team" in text for text in fake.calls[0]))

    def test_http_payload_contract_rejects_tenant_spoof(self) -> None:
        mini_app = APP.MiniVectorSearchApp(FakeEmbed())

        with self.assertRaisesRegex(APP.InputError, "unknown request fields"):
            mini_app.search_payload(
                {"query": "Phoenix status", "mode": "safe", "tenant": "beta"}
            )

    def test_target_url_is_loopback_only(self) -> None:
        self.assertEqual(
            APP.normalize_target_url("http://localhost:8012/"),
            "http://localhost:8012",
        )
        for invalid in (
            "https://localhost:8012",
            "http://10.0.0.1:8012",
            "http://localhost:8012/api/embed",
            "http://user@localhost:8012",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(APP.InputError):
                    APP.normalize_target_url(invalid)

    def test_cli_arguments_have_the_documented_contract(self) -> None:
        args = APP.parse_args(
            ["--query", "Phoenix status", "--mode", "safe", "--top-k", "1"]
        )
        self.assertFalse(args.serve)
        self.assertEqual(args.mode, "safe")
        self.assertEqual(args.top_k, 1)

    def test_invalid_query_mode_and_zero_norm_are_rejected(self) -> None:
        fake = FakeEmbed()
        with self.assertRaisesRegex(APP.InputError, "query"):
            APP.semantic_search(" ", "safe", 2, fake)
        with self.assertRaisesRegex(APP.InputError, "mode"):
            APP.semantic_search("Phoenix status", "other", 2, fake)
        with self.assertRaisesRegex(APP.EmbeddingError, "non-zero norms"):
            APP.cosine_similarity([0.0, 0.0], [1.0, 0.0])


if __name__ == "__main__":
    unittest.main()
