"""Document/evidence binding checks using synthetic records, not AWS proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, 'path', [str(ROOT / 'tests/e2e'), *sys.path]):
    import check_guided_p04_markdown as checker


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        source = 'async def invoke_guarded(body, guardrail, services):\n    pass\n'
        self.document = ("## 1. 문제\n## 2. 풀이\n```bash\n"
            "cat > llm-security-control-plane/guided-labs/h04-bedrock-guardrail/learner.py <<'EOF'\n"
            + source + 'EOF\n```\n')
        cases = [{'case_id': name, 'binding': {'provider_mode': 'aws', 'response': {}},
                  'product': {'effect': 'unchanged'}} for name in
                 ('apply_guardrail-normal', 'apply_guardrail-email', 'converse-normal', 'converse-email')]
        cases[1]['binding']['response'] = {'outputs': [{'text': 'masked'}]}
        cases[3]['binding']['response'] = {'output': {'message': 'masked'}, 'trace': {
            'guardrail': {'outputAssessments': {'policy': [{'sensitiveInformationPolicy': {'piiEntities': []}}]}}}}
        cases += [{'case_id': str(i), 'binding': {'provider_mode': 'contract'}} for i in range(23)]
        digest = hashlib.sha256(source.encode()).hexdigest()
        result = {'task_completed': True, 'security_verdict': 'PASS', 'result': {
            'source_digest': digest, 'provider_mode': 'aws', 'cases': cases}}
        self.evidence = {'checked': True, 'source_digest': digest,
                         'browser': {'response': result}, 'verification': deepcopy(result)}
        self.document += ''.join('출력 예시:\n\n```json\n' + json.dumps(value) + '\n```\n'
                                 for value in checker.expected_examples(cases))

    def test_exact_examples_and_source_match(self):
        self.assertEqual(checker.check(self.document, self.evidence)['exact_output_examples'], 4)

    def test_changed_source_or_output_rejected(self):
        for document in (self.document.replace('    pass', '    return None'),
                         self.document.replace('masked', 'changed'), self.document + '출력 예시:\n```json\n{}\n```\n'):
            with self.subTest(document=document), self.assertRaises(AssertionError):
                checker.check(document, self.evidence)

    def test_stale_incomplete_or_contract_only_proof_rejected(self):
        for mutate in (lambda e: e.update(checked=False),
                       lambda e: e['verification'].update(task_completed=False),
                       lambda e: e['verification']['result'].update(provider_mode='contract'),
                       lambda e: e['verification']['result']['cases'].pop()):
            evidence = deepcopy(self.evidence)
            mutate(evidence)
            with self.assertRaises(AssertionError):
                checker.check(self.document, evidence)

    def test_ambiguous_policy_assessment_rejected(self):
        cases = deepcopy(self.evidence['verification']['result']['cases'])
        cases[3]['binding']['response']['trace']['guardrail']['outputAssessments']['other'] = []
        with self.assertRaises(ValueError):
            checker.expected_examples(cases)


if __name__ == '__main__':
    unittest.main()
