"""Keep publisher solutions outside public assets and Starter COPY instructions.

This supplements the existing HTTP exposure tests; it is not a general image audit.
"""
from pathlib import Path
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[2] / 'llm-security-control-plane'


def unsafe_copies(text):
    failures = []
    for line in text.replace('\\\n', ' ').splitlines():
        if not re.match(r'^\s*(COPY|ADD)\s', line, re.I):
            continue
        words = [word for word in shlex.split(line)[1:] if not word.startswith('--')]
        for source in words[:-1]:
            if source in ('.', './', '*', '/') or 'guided-solutions' in source or 'tests/fixtures' in source:
                failures.append(source)
    return failures


class SolutionBoundaryTests(unittest.TestCase):
    def test_starter_and_public_images_use_explicit_sources(self):
        recipes = list((ROOT / 'guided-labs').glob('*/Containerfile'))
        recipes.append(ROOT / 'guided-control-center/Containerfile')
        self.assertGreaterEqual(len(recipes), 23)
        for recipe in recipes:
            with self.subTest(recipe=recipe):
                self.assertEqual(unsafe_copies(recipe.read_text()), [])

    def test_broad_copy_and_solution_copy_are_detected(self):
        for line in ('COPY . /app', 'COPY guided-solutions/p01.py /app/', 'ADD * /app/'):
            self.assertTrue(unsafe_copies(line))
        self.assertFalse(unsafe_copies('COPY --chmod=0444 guided-labs/a.py /app/'))

    def test_complete_solution_is_not_in_public_assets(self):
        assets = [(ROOT / 'guided-control-center' / name).read_text()
                  for name in ('index.html', 'app.js', 'app.css')]
        for solution in (ROOT / 'guided-solutions').rglob('*'):
            if not solution.is_file() or solution.suffix not in ('.py', '.yaml', '.yml', '.co'):
                continue
            text = solution.read_text().strip()
            if len(text) < 100:
                continue
            with self.subTest(solution=solution):
                self.assertTrue(all(text not in asset for asset in assets))


if __name__ == '__main__':
    unittest.main()
