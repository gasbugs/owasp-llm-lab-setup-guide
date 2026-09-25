"""Bind P04 solution bytes and displayed examples to an actual AWS Browser run."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from p04_markdown import extract_solution


def expected_examples(cases):
    by_name = {row['case_id']: row for row in cases}
    normal = by_name['converse-normal']
    apply = by_name['apply_guardrail-email']['binding']['response']
    converse = by_name['converse-email']['binding']['response']
    assessments = converse['trace']['guardrail']['outputAssessments']
    if len(assessments) != 1:
        raise ValueError('one policy output assessment is required')
    assessment = next(iter(assessments.values()))
    if len(assessment) != 1:
        raise ValueError('one output assessment is required')
    return [normal['product'], apply['outputs'], converse['output'],
            assessment[0]['sensitiveInformationPolicy']]


def check(document, evidence):
    digest = hashlib.sha256(extract_solution(document).encode('utf-8')).hexdigest()
    assert evidence['checked'] is True
    assert evidence['source_digest'] == digest
    response = evidence['browser']['response']
    verification = evidence['verification']
    for result in (response, verification):
        assert result['task_completed'] is True and result['security_verdict'] == 'PASS'
        assert result['result']['source_digest'] == digest
        assert result['result']['provider_mode'] == 'aws'
        assert len(result['result']['cases']) == 27
    cases = response['result']['cases']
    assert cases == verification['result']['cases']
    assert len({row['case_id'] for row in cases}) == 27
    assert sum(row['binding']['provider_mode'] == 'aws' for row in cases) == 4
    examples = [json.loads(raw) for raw in re.findall(
        r'^출력 예시:\s*\n```json\n(.*?)\n```', document, re.MULTILINE | re.DOTALL)]
    assert examples == expected_examples(cases), 'document outputs differ from actual execution'
    return {'verified': True, 'source_digest': digest, 'exact_output_examples': len(examples)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('markdown', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.markdown.read_text(encoding='utf-8'),
                           json.loads(args.evidence.read_text(encoding='utf-8')))))
