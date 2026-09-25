"""Static build-input boundary, not a claim about learner behavior or image contents."""
from pathlib import Path
import hashlib
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane"


def copy_sources(recipe):
    sources = []
    for line in recipe.replace("\\\n", " ").splitlines():
        fields = shlex.split(line, comments=True)
        if not fields:
            continue
        if fields[0].upper() == "ADD":
            raise ValueError("ADD is not an audited local file copy")
        if fields[0].upper() != "COPY":
            continue
        fields = fields[1:]
        while fields and fields[0].startswith("--"):
            if not fields[0].startswith("--chmod="):
                raise ValueError("unaudited COPY option")
            fields.pop(0)
        if len(fields) < 2 or any(character in " ".join(fields) for character in "[]*?$"):
            raise ValueError("COPY must enumerate local files")
        sources.extend(fields[:-1])
    return sources


class GuidedPackagingTests(unittest.TestCase):
    def test_reused_nemo_scaffold_digests_match_current_build_inputs(self):
        verifier = (ROOT / "guided-evidence-verifier/server.py").read_text()
        for number, directory, files in (
            (5, "h05-nemo-dialog", ("Containerfile", "config/config.yml", "server.py")),
            (6, "h06-nemo-action", ("Containerfile", "config/config.yml", "config/flows.co", "server.py")),
            (7, "h07-content-safety", ("Containerfile", "config/prompts.yml", "server.py")),
            (8, "h08-self-check-input", ("Containerfile", "config/config.yml", "server.py")),
            (10, "h10-self-check-output", ("Containerfile", "server.py", "config/config.yml")),
        ):
            with self.subTest(activity=number):
                digest = hashlib.sha256()
                for name in files:
                    digest.update(name.encode())
                    digest.update((ROOT / "guided-labs" / directory / name).read_bytes())
                expected = re.search(rf'H{number:02d}_SCAFFOLD_DIGEST = "([a-f0-9]+)"', verifier)[1]
                self.assertEqual(digest.hexdigest(), expected)

    def test_every_guided_recipe_copies_only_explicit_existing_files(self):
        recipes = sorted(ROOT.glob("guided-*/Containerfile*"))
        recipes += sorted((ROOT / "guided-labs").glob("*/Containerfile*"))
        self.assertGreater(len(recipes), 25)
        for recipe in recipes:
            with self.subTest(recipe=str(recipe.relative_to(ROOT))):
                sources = copy_sources(recipe.read_text())
                self.assertTrue(sources)
                for source in sources:
                    path = ROOT / source
                    self.assertTrue(path.is_file(), source)
                    self.assertFalse(path.is_symlink(), source)
                    self.assertTrue(path.resolve().is_relative_to(ROOT.resolve()), source)
                    self.assertFalse(set(path.parts) & {"tests", "solutions", ".state", "evidence"}, source)

    def test_nemo_config_copy_is_an_exact_file_allowlist(self):
        for number, name, second in (
            (5, "nemo-dialog", "flows.co"), (6, "nemo-action", "flows.co"),
            (7, "content-safety", "prompts.yml"), (8, "self-check-input", "prompts.yml"),
            (10, "self-check-output", "prompts.yml"),
        ):
            prefix = f"guided-labs/h{number:02d}-{name}/config/"
            recipe = ROOT / prefix / "../Containerfile"
            actual = {source for source in copy_sources(recipe.read_text()) if "/config/" in source}
            self.assertEqual(actual, {prefix + "config.yml", prefix + second})

    def test_unsupported_copy_forms_are_not_silently_accepted(self):
        for recipe in ("ADD https://example.invalid/a /app/", "COPY *.py /app/",
                       'COPY ["source.py", "/app/"]', "COPY --from=builder /app /app"):
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                copy_sources(recipe)


if __name__ == "__main__":
    unittest.main()
