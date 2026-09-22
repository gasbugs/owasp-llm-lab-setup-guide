import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "llmgoat-local-build"


class LlmgoatLocalBuildExampleTests(unittest.TestCase):
    def test_containerfile_pins_runtime_and_embeds_matching_source(self):
        containerfile = (EXAMPLE / "Containerfile").read_text(encoding="utf-8")

        self.assertIn(
            "ghcr.io/secforce/llmgoat-gpu:v0.1.0@sha256:"
            "b17ac2038813de509a5cabe4f284b1119c7d0c025b9f63166854688f52698611",
            containerfile,
        )
        self.assertIn("codeload.github.com/gasbugs/LLMGoat", containerfile)
        self.assertNotIn("ghcr.io/gasbugs/llmgoat-gpu", containerfile)
        self.assertIn(
            "ADD --checksum=sha256:"
            "4e3251ebd6ae59a4003791e18606a23ae94708bb48236caf51aa51cffbe34e29",
            containerfile,
        )
        self.assertIn("/usr/src/llmgoat-v0.1.0", containerfile)
        self.assertIn("/usr/share/licenses/llmgoat/GPL-3.0.txt", containerfile)
        self.assertNotIn("llmgoat-gpu:latest", containerfile)

        fallback = (EXAMPLE / "Containerfile.source-build").read_text(
            encoding="utf-8"
        )
        self.assertIn("nvidia/cuda:12.2.2-devel-ubuntu22.04@sha256:", fallback)
        self.assertIn("llama-cpp-python==0.3.16", fallback)

    def test_compose_uses_isolated_names_and_local_build_then_up(self):
        compose = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
        guide = (EXAMPLE / "README.md").read_text(encoding="utf-8")

        self.assertIn("name: llmgoat-local-build", compose)
        self.assertIn('container_name: llmgoat-local-build', compose)
        self.assertIn('- "15000:5000"', compose)
        self.assertIn("pull_policy: never", compose)
        self.assertIn("docker compose build", guide)
        self.assertIn("docker compose up -d", guide)
        self.assertIn("LLMGOAT_DOCKERFILE=Containerfile.source-build", guide)
        self.assertNotIn("docker compose up -d --build", guide)
        self.assertIn("llama-cpp-python", guide)
        self.assertNotIn("ollama:", compose)
        self.assertIn("기존 5000번 대신 15000번", guide)


if __name__ == "__main__":
    unittest.main()
