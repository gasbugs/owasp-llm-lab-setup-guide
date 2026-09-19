"""DVLA model transport regression; no agent tools or remote models are invoked."""
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "docker/dvla" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DvlaModelClientTests(unittest.TestCase):
    def test_ollama_uses_native_chat_and_disables_thinking(self):
        client = load("model_client")
        native, legacy = Mock(), Mock()
        modules = {"langchain_ollama": SimpleNamespace(ChatOllama=native),
                   "langchain_litellm": SimpleNamespace(ChatLiteLLM=legacy)}
        with patch.dict(sys.modules, modules), patch.dict(
            client.os.environ, {"OLLAMA_API_BASE": "http://ollama:11434"}, clear=True
        ):
            for provider in ("ollama", "ollama_chat"):
                client.create_chat_model(model=f"{provider}/qwen3:14b-q4_K_M", streaming=True)
                native.assert_called_with(model="qwen3:14b-q4_K_M", base_url="http://ollama:11434",
                                          temperature=0, reasoning=False, disable_streaming=False)
        legacy.assert_not_called()

    def test_non_ollama_keeps_litellm(self):
        client = load("model_client")
        legacy = Mock()
        with patch.dict(sys.modules, {"langchain_litellm": SimpleNamespace(ChatLiteLLM=legacy)}):
            client.create_chat_model(model="openai/example", streaming=False, temperature=0.2)
        legacy.assert_called_once_with(model="openai/example", streaming=False, temperature=0.2)

    def test_host_fallback_and_non_streaming_are_preserved(self):
        client = load("model_client")
        native = Mock()
        with patch.dict(sys.modules, {"langchain_ollama": SimpleNamespace(ChatOllama=native)}), \
             patch.dict(client.os.environ, {"OLLAMA_HOST": "http://ollama:11434"}, clear=True):
            client.create_chat_model(model="ollama/qwen3:14b-q4_K_M", streaming=False)
        self.assertTrue(native.call_args.kwargs["disable_streaming"])
        self.assertEqual(native.call_args.kwargs["base_url"], "http://ollama:11434")

    def test_build_patch_only_changes_constructor_import(self):
        configure = load("configure_model_client").configure
        old = "from langchain_litellm import ChatLiteLLM"
        new = "from model_client import create_chat_model as ChatLiteLLM"
        source = old + "\n# untouched upstream agent and tools\n"
        result = configure(source)
        self.assertEqual(result.replace(new, old), source)
        for invalid in ("", old + "\n" + old):
            with self.assertRaises(ValueError):
                configure(invalid)

    def test_image_installs_and_activates_pinned_transport(self):
        dockerfile = (ROOT / "docker/dvla/Dockerfile").read_text()
        self.assertIn("-r requirements-ollama.txt", dockerfile)
        self.assertIn("RUN python /app/configure_model_client.py /app/main.py", dockerfile)
        self.assertIn("langchain-ollama==0.3.10", (ROOT / "docker/dvla/requirements-ollama.txt").read_text())
        self.assertIn("${DVLA_IMAGE_TAG:-${COMPOSE_IMAGE_TAG:-latest}}",
                      (ROOT / "infrastructure/compose/compose.yaml").read_text())


if __name__ == "__main__":
    unittest.main()
