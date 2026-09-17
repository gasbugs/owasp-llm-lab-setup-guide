"""Normal HTTP payload contracts for the non-thinking main model."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
MODEL = "qwen3:14b-q4_K_M"


def load_client(app):
    spec = importlib.util.spec_from_file_location(
        f"{app}_llm", ROOT / "docker" / app / "app" / "llm.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MainModelTest(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, app, *, structured=False):
        module = load_client(app)
        response = MagicMock()
        response.json.return_value = {
            "message": {"content": json.dumps({"ok": True}) if structured else "안녕하세요"}
        }
        http = AsyncMock()
        http.post.return_value = response
        with patch.dict(module.os.environ, {}, clear=True), patch.object(
            module.httpx, "AsyncClient"
        ) as factory:
            factory.return_value.__aenter__.return_value = http
            client = module.LLMClient()
            if structured:
                result = await client.structured_chat("system", "hello", {"type": "object"})
                self.assertEqual(result, {"ok": True})
            else:
                result = await client.chat("system", "hello")
                self.assertEqual(result, "안녕하세요")
        payload = http.post.call_args.kwargs["json"]
        self.assertEqual(payload["model"], MODEL)
        self.assertIs(payload["think"], False)
        self.assertIs(payload["stream"], False)
        response.raise_for_status.assert_called_once()

    async def test_rag_chat(self):
        await self.invoke("vuln-rag")

    async def test_rag_structured_chat(self):
        await self.invoke("vuln-rag", structured=True)

    async def test_agent_chat(self):
        await self.invoke("vuln-agent")

    def test_deployment_defaults_agree(self):
        for path in (
            "docker/vuln-rag/Dockerfile", "docker/vuln-agent/Dockerfile",
            "infrastructure/compose/compose.yaml",
            "infrastructure/scripts/student/install-lab.sh",
            "infrastructure/scripts/student/recreate-editable-lab",
            "infrastructure/terraform/variables.tf", "infrastructure/packer/ami.pkr.hcl",
        ):
            with self.subTest(path=path):
                content = (ROOT / path).read_text()
                self.assertIn(MODEL, content)
                self.assertNotIn("llama3.1:8b-instruct-q4_K_M", content)

    def test_bootstrap_does_not_install_guard_model(self):
        content = (ROOT / "infrastructure/scripts/student/install-lab.sh").read_text()
        self.assertNotIn("OLLAMA_GUARD_MODEL", content)
        self.assertNotIn("llama-guard", content)
        self.assertIn("OLLAMA_EMBED_MODEL", content)


if __name__ == "__main__":
    unittest.main()
