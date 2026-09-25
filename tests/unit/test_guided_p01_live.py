"""P01 publisher source extraction; no Docker or cloud operations."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), *sys.path]):
    spec = importlib.util.spec_from_file_location('p01_live_check', ROOT / 'tests/e2e/check_guided_p01_live.py')
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)


class P01PublisherTests(unittest.TestCase):
    def extract(self, document):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'problem.md'
            path.write_text(document)
            return publisher.markdown_source(path)

    def test_exact_solution_bytes_not_problem_example(self):
        code = 'def handle_request(body, client):\n    # 한글 주석\n    return body\n'
        document = '# P01\n```python\nnot_solution()\n```\n## 6. 풀이 — 구현\n```python\n' + code + '```\n'
        self.assertEqual(self.extract(document), code.encode())

    def test_missing_ambiguous_wrong_interface_and_oversized_rejected(self):
        valid = '## 6. 풀이\n```python\ndef handle_request(body, client):\n    return body\n```\n'
        for document in ('# no solution', valid + valid,
                         valid.replace('handle_request', 'wrong_name'),
                         valid.replace('    return body', '    #' + 'x' * 65536),
                         valid.replace('return body', 'return !')):
            with self.subTest(document=document[:40]), self.assertRaises((ValueError, SyntaxError)):
                self.extract(document)


if __name__ == '__main__':
    unittest.main()
