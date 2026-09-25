"""P12 document extraction preserves bytes; functional correctness is a separate E2E."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/p12_markdown.py'
spec = importlib.util.spec_from_file_location('p12_markdown', PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class P12MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.source = '# 실제 단계를 연결한다.\nasync def handle_request(request, services):\n    pass\n'
        self.document = ("# P12\n## 1. 문제\n## 2. 풀이\n```bash\n"
            "cat > llm-security-control-plane/guided-labs/h12-application-pipeline/pipeline.py <<'EOF'\n"
            + self.source + 'EOF\nfalse\n```\n')

    def test_exact_source_bytes_not_shell_execution(self):
        self.assertEqual(checker.extract_solution(self.document), self.source)
        self.assertEqual(checker.extract_solution(self.document.replace('## 2. 풀이', '## 2. 풀이: 단계 연결')),
                         self.source)

    def test_missing_duplicate_and_wrong_target_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 적용'),
                         self.document + '\n## 3. 풀이\n', self.document + self.document,
                         self.document.replace('pipeline.py', 'server.py'),
                         self.document.replace("<<'EOF'", '<<EOF')):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)

    def test_problem_code_never_substitutes_for_solution(self):
        document = self.document.replace('## 2. 풀이\n', '') + '\n## 2. 풀이\n'
        with self.assertRaises(ValueError):
            checker.extract_solution(document)

    def test_syntax_missing_async_and_size_limit(self):
        for source in ('def broken(', 'def handle_request(request, services):\n    pass\n',
                       self.source + '#' + 'x' * 65536):
            with self.subTest(source=source[:50]), self.assertRaises(ValueError):
                checker.extract_solution(self.document.replace(self.source, source))


if __name__ == '__main__':
    unittest.main()
