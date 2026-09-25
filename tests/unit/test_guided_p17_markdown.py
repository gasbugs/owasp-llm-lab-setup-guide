"""P17 Markdown extraction preserves the exact published function."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/p17_markdown.py'
spec = importlib.util.spec_from_file_location('p17_markdown', PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class P17MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.source = '# 실제 업무를 감싼다.\ndef observe_request(*args):\n    pass\n'
        self.document = ("# P17\n## 1. 문제\n## 2. 풀이\n```bash\n"
            "cat > llm-security-control-plane/guided-labs/h17-telemetry/instrumentation.py <<'EOF'\n"
            + self.source + "EOF\nfalse\n```\n")

    def test_exact_bytes_and_comments_without_shell_execution(self):
        self.assertEqual(checker.extract_solution(self.document), self.source)

    def test_ambiguous_or_missing_solution_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 힌트'),
                         self.document + '\n## 3. 풀이\n',
                         self.document.replace('instrumentation.py', 'another.py'),
                         self.document.replace("<<'EOF'", '<<EOF'),
                         self.document + self.document):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)

    def test_problem_code_never_substitutes_for_solution(self):
        document = self.document.replace('## 2. 풀이\n', '') + '\n## 2. 풀이\n'
        with self.assertRaises(ValueError):
            checker.extract_solution(document)


if __name__ == '__main__':
    unittest.main()
