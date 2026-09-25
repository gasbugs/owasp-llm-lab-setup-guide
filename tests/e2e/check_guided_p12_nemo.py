"""Real NeMo native rails with explicit deterministic LLM responses, not live AWS classification."""
import importlib.util
import json
import sys
from pathlib import Path
import unittest

from nemoguardrails.types import LLMResponse

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-protected-services/nemo.py"
spec = importlib.util.spec_from_file_location("p12_nemo", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
retrieval_spec = importlib.util.spec_from_file_location("p12_retrieval", SOURCE.with_name("retrieval.py"))
retrieval = importlib.util.module_from_spec(retrieval_spec)
retrieval_spec.loader.exec_module(retrieval)


class FixtureModel:
    model_name = "p12-deterministic-classifier-fixture"
    provider_name = "test-fixture-no-network"
    provider_url = None

    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    async def generate_async(self, prompt, *, stop=None, **kwargs):
        self.calls.append({"prompt": prompt, "stop": stop, "kwargs": kwargs})
        if isinstance(self.answer, Exception):
            raise self.answer
        return LLMResponse(content=self.answer, model=self.model_name)

    async def stream_async(self, prompt, *, stop=None, **kwargs):
        raise AssertionError("stream not part of the classifier contract")
        yield


class NativeRailTests(unittest.IsolatedAsyncioTestCase):
    records = []

    async def test_native_allow_and_block_for_input_and_output(self):
        for stage in module.STAGES:
            for answer in ("No", "Yes"):
                with self.subTest(stage=stage, answer=answer):
                    model = FixtureModel(answer)
                    result = await module.check_text(stage, "교육용 검사 문장", model)
                    self.assertEqual(result["allowed"], answer == "No")
                    self.assertEqual(len(model.calls), 1)
                    self.assertEqual(model.calls[0]["kwargs"]["max_tokens"], 3)
                    self.assertEqual(model.calls[0]["kwargs"]["temperature"], 0.0)
                    self.assertIn("교육용 검사 문장", str(model.calls[0]["prompt"]))
                    self.assertEqual(result["evidence"]["version"], "0.22.0")
                    self.assertNotIn("교육용 검사 문장", json.dumps(result, ensure_ascii=False))
                    self.assertNotIn("task_completed", result)
                    self.assertIn(module.STAGES[stage][1], result["evidence"]["actions"])
                    self.records.append(result)

    async def test_malformed_classifier_never_becomes_successful_defense(self):
        for stage in module.STAGES:
            for answer in ("maybe", "YES", "Yes\n", "", "No, this is safe", "No\n\nThe"):
                with self.subTest(stage=stage, answer=answer), self.assertRaises(ValueError):
                    await module.check_text(stage, "교육용 검사 문장", FixtureModel(answer))

    async def test_provider_error_is_not_a_normal_block(self):
        with self.assertRaises(Exception):
            await module.check_text("input_rail", "교육용 검사 문장", FixtureModel(RuntimeError("offline")))

    async def test_invalid_inputs_never_call_model(self):
        for stage, text in (("main", "hello"), ("retrieval_rail", "hello"), ("input_rail", "")):
            model = FixtureModel("No")
            with self.assertRaises(ValueError):
                await module.check_text(stage, text, model)
            self.assertEqual(model.calls, [])

    async def test_retrieval_hook_checks_supplied_chunks_before_static_response(self):
        for answer in ("No", "Yes"):
            with self.subTest(answer=answer):
                model = FixtureModel(answer)
                result = await retrieval.check_retrieved_text("검색된 교육용 문서", model)
                self.assertEqual(result["allowed"], answer == "No")
                self.assertEqual(len(model.calls), 1)
                self.assertIn("검색된 교육용 문서", str(model.calls[0]["prompt"]))
                self.assertEqual(model.calls[0]["kwargs"]["max_tokens"], 3)
                self.assertEqual(result["evidence"]["actions"][:2],
                                 ["retrieve_relevant_chunks", "inspect_p12_chunks"])
                self.assertEqual("generate_bot_message" in result["evidence"]["actions"], answer == "No")
                self.assertEqual(result["evidence"]["llm_call"]["task"], "p12_retrieval_check")
                self.assertNotIn("검색된 교육용 문서", json.dumps(result, ensure_ascii=False))
                self.records.append(result)

    async def test_retrieval_classifier_errors_are_not_normal_blocks(self):
        for answer in ("maybe", "YES", "Yes\n", "", "No, this is safe", "No\n\nThe", RuntimeError("offline")):
            with self.subTest(answer=str(answer)), self.assertNoLogs("nemoguardrails", level="ERROR"), self.assertRaisesRegex(ValueError, "retrieval classifier failed"):
                await retrieval.check_retrieved_text("검색된 교육용 문서", FixtureModel(answer))

    async def test_retrieval_invalid_text_never_calls_model(self):
        for text in (None, {}, "", " ", "a" * 16001):
            model = FixtureModel("No")
            with self.assertRaises(ValueError):
                await retrieval.check_retrieved_text(text, model)
            self.assertEqual(model.calls, [])


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    if not program.result.wasSuccessful():
        sys.exit(1)
    print(json.dumps({"scope": "actual NeMo 0.22 input/output and custom retrieval rails; deterministic classifier fixture, no AWS or external retrieval",
                      "tests": program.result.testsRun, "native_results": NativeRailTests.records}, ensure_ascii=False))
