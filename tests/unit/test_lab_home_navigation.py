from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class LabHomeNavigationTests(unittest.TestCase):
    def test_first_party_lab_pages_link_to_current_host_portal(self) -> None:
        for relative in (
            "docker/vuln-rag/app/templates/index.html",
            "docker/vuln-agent/app/templates/index.html",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertIn('id="portal-home"', source)
                self.assertIn("http://${window.location.hostname}:8080/", source)

        agent = (ROOT / "docker/vuln-agent/app/templates/index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('name="viewport" content="width=device-width, initial-scale=1"', agent)

    def test_llmgoat_wrapper_injects_home_link_into_html_only(self) -> None:
        source = (ROOT / "docker/llmgoat/health_entrypoint.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('@app.after_request', source)
        self.assertIn('response.mimetype == "text/html"', source)
        self.assertIn("http://${window.location.hostname}:8080/", source)
        self.assertIn("z-index:9000", source)
        self.assertNotIn("z-index:2147483647", source)

    def test_dvla_keeps_upstream_pin_and_adds_small_component(self) -> None:
        dockerfile = (ROOT / "docker/dvla/Dockerfile").read_text(encoding="utf-8")
        component = (ROOT / "docker/dvla/home_link.py").read_text(encoding="utf-8")
        self.assertIn("ARG REPO_REF=c0cf9a14adad76e9d6a53c41741f625334bd9971", dockerfile)
        self.assertIn("COPY home_link.py /app/home_link.py", dockerfile)
        self.assertIn("render_portal_home", dockerfile)
        self.assertIn("window.parent.location.hostname", component)
        self.assertIn(":8080/", component)


if __name__ == "__main__":
    unittest.main()
