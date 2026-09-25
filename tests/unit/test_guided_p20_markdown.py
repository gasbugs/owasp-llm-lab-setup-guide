"""Extract exact P20 artifacts only from the later solution section."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('p20_markdown',
    Path(__file__).resolve().parents[2] / 'tests/e2e/p20_markdown.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def block(name, content):
    return "cat > llm-security-control-plane/guided-labs/h20-alert-dashboard/" + name + " <<'EOF'\n" + content + "\nEOF\n"


class P20MarkdownTests(unittest.TestCase):
    def document(self):
        return '## 4. 풀이: 설정\n' + block('rules.yaml', 'groups: []') + block('dashboard.json', '{"panels": []}')

    def test_preserves_exact_bytes_and_ignores_problem_example(self):
        document = block('rules.yaml', 'do not use') + self.document()
        self.assertEqual(module.extract_solution(document), {
            'rules.yaml': 'groups: []\n', 'dashboard.json': '{"panels": []}\n'})

    def test_missing_or_duplicate_file_rejected(self):
        for document in ('## 1. 풀이\n' + block('rules.yaml', 'groups: []'),
                         self.document() + block('rules.yaml', 'groups: []')):
            with self.assertRaises(ValueError):
                module.extract_solution(document)

    def test_missing_or_duplicate_solution_rejected(self):
        for document in ('no solution', self.document() + '\n## 5. 풀이\n'):
            with self.assertRaises(ValueError):
                module.extract_solution(document)


if __name__ == '__main__':
    unittest.main()
