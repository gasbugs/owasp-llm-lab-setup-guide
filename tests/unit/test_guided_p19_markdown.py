"""Extract the P19 implementation without evaluating any Markdown shell."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/check_guided_p19_implementation.py'
spec = importlib.util.spec_from_file_location('p19_markdown', PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class P19MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.source = '# 설명을 보존한다.\ndef analyze_incident(bundle, request_id):\n    raise ValueError()\n'
        self.document = ("# P19\n## 1. 문제\n## 2. 풀이\n```bash\n"
            "cat > llm-security-control-plane/guided-labs/h19-incident-investigation/investigation.py <<'EOF'\n"
            + self.source + "EOF\nfalse\n```\n")

    def test_exact_source_preserves_comments_and_final_newline(self):
        self.assertEqual(checker.extract_solution(self.document), self.source)

    def test_missing_or_ambiguous_solution_is_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 힌트'),
                         self.document + '\n## 3. 풀이\n',
                         self.document.replace('investigation.py', 'another.py'),
                         self.document.replace("<<'EOF'", '<<EOF')):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)

    def test_solution_before_problem_is_not_extracted(self):
        document = self.document.replace('## 2. 풀이\n', '') + '\n## 2. 풀이\n'
        with self.assertRaises(ValueError):
            checker.extract_solution(document)


if __name__ == '__main__':
    unittest.main()
