from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ReverseProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = (
            ROOT / "infrastructure/reverse-proxy/default.conf"
        ).read_text(encoding="utf-8")
        cls.compose = (
            ROOT / "infrastructure/compose/compose.yaml"
        ).read_text(encoding="utf-8")

    def test_port_80_routes_module_00_to_05_browser_services(self) -> None:
        routes = {
            "/prompt-rag/": "http://prompt_rag_backend/",
            "/llm04-rag/": "http://llm04_rag_backend/",
            "/data-rag/": "http://data_rag_backend/",
            "/output-rag/": "http://output_rag_backend/",
            "/knowledge-rag/": "http://knowledge_rag_backend/",
            "/resource-rag/": "http://resource_rag_backend/",
            "/vuln-agent/": "http://vuln_agent_backend/",
            "/llmgoat/": "http://llmgoat_backend",
            "/dvla/": "http://dvla_backend",
        }
        for path, upstream in routes.items():
            with self.subTest(path=path):
                self.assertIn(f"location {path}", self.config)
                self.assertIn(f"proxy_pass {upstream};", self.config)

    def test_proxy_preserves_websocket_and_long_request_support(self) -> None:
        self.assertIn("proxy_set_header Upgrade $http_upgrade;", self.config)
        self.assertIn("proxy_set_header Connection $connection_upgrade;", self.config)
        self.assertIn("client_max_body_size 0;", self.config)
        self.assertIn("proxy_read_timeout 600s;", self.config)

    def test_proxy_re_resolves_compose_dns_after_service_recreation(self) -> None:
        self.assertIn("resolver 127.0.0.11 valid=10s ipv6=off;", self.config)
        for service, port in (
            ("prompt-rag", 8000),
            ("llm04-rag", 8004),
            ("data-rag", 8010),
            ("output-rag", 8011),
            ("vuln-agent", 8001),
            ("llmgoat", 5000),
            ("dvla", 8501),
        ):
            with self.subTest(service=service):
                self.assertIn(f"server {service}:{port} resolve;", self.config)

    def test_compose_publishes_proxy_and_keeps_legacy_ports(self) -> None:
        self.assertIn("container_name: lab-reverse-proxy", self.compose)
        self.assertIn("docker.io/library/nginx:1.31.5-alpine3.24", self.compose)
        self.assertIn('"80:80"', self.compose)
        self.assertIn('"8501:8501"', self.compose)
        for port in (5000, 8000, 8001, 8002, 8004, 8010, 8011, 8012, 8013, 8080):
            with self.subTest(port=port):
                self.assertIn(f'"{port}:{port}"', self.compose)

    def test_dvla_legacy_health_is_forwarded_to_its_base_path(self) -> None:
        self.assertIn("location = /_stcore/health", self.config)
        self.assertIn(
            "proxy_pass http://dvla_backend/dvla/_stcore/health;", self.config
        )


if __name__ == "__main__":
    unittest.main()
