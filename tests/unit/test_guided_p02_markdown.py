"""Document extraction preserves source bytes, not a substitute for functional E2E."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/p02_markdown.py'
spec = importlib.util.spec_from_file_location('p02_markdown', PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.source = '# 원문 저장과 변환을 연결한다.\nasync def prepare_document(body, document_id, services):\n    pass\n'
        self.document = ("# P02\n## 1. 문제\n## 2. 풀이\n```bash\n"
            "cat > llm-security-control-plane/guided-labs/h02-document-ingestion/learner.py <<'EOF'\n"
            + self.source + 'EOF\nfalse\n```\n')

    def test_exact_bytes_without_shell_execution(self):
        self.assertEqual(checker.extract_solution(self.document), self.source)

    def test_missing_duplicate_and_wrong_target_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 적용'),
                         self.document + '\n## 3. 풀이\n', self.document + self.document,
                         self.document.replace('learner.py', 'server.py'),
                         self.document.replace("<<'EOF'", '<<EOF')):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)

    def test_problem_code_cannot_substitute_for_solution(self):
        document = self.document.replace('## 2. 풀이\n', '') + '\n## 2. 풀이\n'
        with self.assertRaises(ValueError):
            checker.extract_solution(document)

    def test_invalid_syntax_sync_function_and_oversize_rejected(self):
        for source in ('def broken(', 'def prepare_document(body, document_id, services):\n    pass\n',
                       self.source + '#' + 'x' * 65536):
            with self.subTest(source=source[:50]), self.assertRaises(ValueError):
                checker.extract_solution(self.document.replace(self.source, source))


if __name__ == '__main__':
    unittest.main()
