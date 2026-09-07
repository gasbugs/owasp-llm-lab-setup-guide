import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class Llm03ToolsImageTests(unittest.TestCase):
    def test_image_keeps_toolchain_and_license_provenance(self):
        dockerfile = (ROOT / "examples/llm03/Dockerfile.llama-cpp").read_text()

        self.assertIn(
            "635cdd5fcc5bdeb8ec2e108bb2a40acf62d9039b",
            dockerfile,
        )
        self.assertIn("org.opencontainers.image.licenses=\"MIT\"", dockerfile)
        self.assertIn(
            "COPY --from=build /src/llama.cpp/LICENSE "
            "/usr/share/licenses/llama.cpp/LICENSE",
            dockerfile,
        )

    def test_workflow_publishes_an_immutable_amd64_image(self):
        workflow = (ROOT / ".github/workflows/llm03-tools.yaml").read_text()

        self.assertIn("ghcr.io/gasbugs/owasp-llm-llm03-tools", workflow)
        self.assertIn("SHA_TAG: sha-${{ github.sha }}", workflow)
        self.assertIn("file: ./examples/llm03/Dockerfile.llama-cpp", workflow)
        self.assertIn("platforms: linux/amd64", workflow)
        self.assertNotIn("tags: ${{ env.IMAGE }}:latest", workflow)


if __name__ == "__main__":
    unittest.main()
