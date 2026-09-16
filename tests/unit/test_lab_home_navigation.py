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
                self.assertIn("http://${window.location.hostname}/", source)
                self.assertIn("const appUrl", source)

        agent = (ROOT / "docker/vuln-agent/app/templates/index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('name="viewport" content="width=device-width, initial-scale=1"', agent)

    def test_llmgoat_mounts_the_upstream_app_below_its_proxy_path(self) -> None:
        dockerfile = (ROOT / "docker/llmgoat/Dockerfile").read_text(encoding="utf-8")
        wrapper = (ROOT / "docker/llmgoat/proxy_entrypoint.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("COPY proxy_entrypoint.py", dockerfile)
        self.assertIn("ENTRYPOINT", dockerfile)
        self.assertIn("UriPrefixMiddleware", wrapper)
        self.assertIn('MOUNT_PATH = "/llmgoat"', wrapper)
        self.assertIn('"text/css"', wrapper)

    def test_dvla_keeps_upstream_app_unmodified(self) -> None:
        dockerfile = (ROOT / "docker/dvla/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG REPO_REF=c0cf9a14adad76e9d6a53c41741f625334bd9971", dockerfile)
        self.assertNotIn("home_link.py", dockerfile)
        self.assertNotIn("render_portal_home", dockerfile)
        self.assertNotIn("sed -i '/st.set_page_config", dockerfile)
        self.assertFalse((ROOT / "docker/dvla/home_link.py").exists())
        self.assertIn("--server.baseUrlPath=dvla", dockerfile)


if __name__ == "__main__":
    unittest.main()
