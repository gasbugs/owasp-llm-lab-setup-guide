"""Extract only the declared P18 solution; never execute Markdown shell blocks."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'e2e/check_guided_p18_markdown.py'
spec = importlib.util.spec_from_file_location('p18_markdown', SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class P18MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.body = "# CUSTOM FILE\nlogql: test\npromql: test\ntrace_lookup: exact_trace_id\n"
        self.document = ("# P18\n## 1. 문제\n## 2. 풀이\n```bash\n"
                         "cat > llm-security-control-plane/guided-labs/h18-product-queries/queries.yaml <<'EOF'\n"
                         + self.body + "EOF\n```\n")

    def test_exact_solution_preserves_comments_and_final_newline(self):
        self.assertEqual(checker.extract_solution(self.document), self.body)

    def test_other_commands_are_not_executed(self):
        document = self.document.replace('```\n', 'false\n```\n')
        self.assertEqual(checker.extract_solution(document), self.body)

    def test_missing_or_duplicate_solution_is_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 힌트'),
                         self.document + '## 3. 풀이\n',
                         self.document.replace('queries.yaml', 'another.yaml'),
                         self.document.replace("<<'EOF'", '<<EOF')):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)


if __name__ == '__main__':
    unittest.main()
