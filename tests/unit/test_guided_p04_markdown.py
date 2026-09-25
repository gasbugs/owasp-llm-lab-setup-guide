"""Extraction is not functional grading; no shell or AWS calls are made here."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'e2e/p04_markdown.py'
spec = importlib.util.spec_from_file_location('p04_markdown', PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class MarkdownTests(unittest.TestCase):
    def setUp(self):
        self.source = '# 입력을 확인한다.\nasync def invoke_guarded(body, guardrail, services):\n    pass\n'
        self.command = "cat > llm-security-control-plane/guided-labs/h04-bedrock-guardrail/learner.py <<'EOF'\n"
        self.document = ('# P04\n## 1. 문제\n## 2. 풀이 — 정책 연결\n```bash\n'
                         + self.command + self.source + 'EOF\nfalse\n```\n')

    def test_exact_source_preserved_without_shell_execution(self):
        self.assertEqual(checker.extract_solution(self.document), self.source)

    def test_missing_duplicate_and_wrong_target_rejected(self):
        for document in (self.document.replace('## 2. 풀이', '## 2. 적용'),
                         self.document + '\n## 3. 풀이\n',
                         self.document + self.command + self.source + 'EOF\n',
                         self.document.replace('learner.py', 'server.py'),
                         self.document.replace("<<'EOF'", '<<EOF')):
            with self.subTest(document=document), self.assertRaises(ValueError):
                checker.extract_solution(document)

    def test_problem_code_cannot_substitute_for_solution(self):
        document = self.document.replace('## 2. 풀이 — 정책 연결\n', '') + '\n## 2. 풀이\n'
        with self.assertRaises(ValueError):
            checker.extract_solution(document)

    def test_invalid_sync_wrong_and_duplicate_function_rejected(self):
        for source in ('def broken(', self.source.replace('async def', 'def'),
                       self.source.replace('invoke_guarded', 'wrong'), self.source + self.source):
            with self.subTest(source=source), self.assertRaises(ValueError):
                checker.extract_solution(self.document.replace(self.source, source))

    def test_limit_is_utf8_bytes(self):
        source = self.source + '#' + '가' * 22000 + '\n'
        self.assertLess(len(source), 65536)
        with self.assertRaises(ValueError):
            checker.extract_solution(self.document.replace(self.source, source))

    def test_comments_and_alternative_code_are_not_answer_hashes(self):
        source = self.source.replace('    pass', '    # 다른 구현도 허용한다.\n    return None')
        self.assertEqual(checker.extract_solution(self.document.replace(self.source, source)), source)


if __name__ == '__main__':
    unittest.main()
