from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = ROOT / "infrastructure/portal/server.py"
SPEC = spec_from_file_location("portal_status_server", SERVER_PATH)
assert SPEC and SPEC.loader
SERVER = module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)


class FakeResponse:
    def __init__(self, status: int):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class PortalStatusServerTests(TestCase):
    def test_targets_are_fixed_compose_services(self) -> None:
        self.assertEqual(
            SERVER.SERVICES,
            {
                "prompt-rag": "http://prompt-rag:8000/healthz",
                "data-rag": "http://data-rag:8010/healthz",
                "output-rag": "http://output-rag:8011/healthz",
                "knowledge-rag": "http://knowledge-rag:8012/healthz",
                "resource-rag": "http://resource-rag:8013/healthz",
                "vuln-agent": "http://vuln-agent:8001/healthz",
                "llmgoat": "http://llmgoat:5000/healthz",
                "dvla": "http://dvla:8501/_stcore/health",
                "fake-registry": "http://fake-registry:8002/api/v1/models",
                "ollama": "http://ollama:11434/api/tags",
            },
        )
        for target in SERVER.SERVICES.values():
            with self.subTest(target=target):
                self.assertTrue(target.startswith("http://"))
                self.assertNotIn("127.0.0.1", target)

    def test_only_2xx_is_online(self) -> None:
        with patch.object(SERVER, "urlopen", return_value=FakeResponse(204)):
            result = SERVER.check_service("prompt-rag")
        self.assertEqual(result["online"], True)
        self.assertEqual(result["status"], 204)

    def test_http_error_is_offline_with_status(self) -> None:
        error = HTTPError("http://prompt-rag:8000/healthz", 500, "error", None, None)
        with patch.object(SERVER, "urlopen", side_effect=error):
            result = SERVER.check_service("prompt-rag")
        self.assertEqual(result, {"service": "prompt-rag", "online": False, "status": 500})

    def test_connection_error_is_offline_without_status(self) -> None:
        with patch.object(SERVER, "urlopen", side_effect=URLError("unreachable")):
            result = SERVER.check_service("prompt-rag")
        self.assertEqual(result, {"service": "prompt-rag", "online": False, "status": None})
