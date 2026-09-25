"""Bind P03's final solution and exact examples to its actual AWS/Browser run."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from p03_markdown import extract_solution


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
        assert len(result['result']['cases']) == 19
    assert response['result']['cases'] == verification['result']['cases']
    cases = {row['case_id']: row for row in response['result']['cases']}
    assert len(cases) == 19
    assert sum(row['provider_mode'] == 'aws' for row in cases.values()) == 1
    assert cases['current-complete']['provider_mode'] == 'aws'
    examples = [json.loads(raw) for raw in re.findall(
        r'^출력 예시:\s*\n```json\n(.*?)\n```', document, re.MULTILINE | re.DOTALL)]
    assert examples == [cases[name] for name in ('current-complete', 'queued', 'different-job')], \
        'document outputs differ from actual execution'
    return {'verified': True, 'source_digest': digest, 'exact_output_examples': len(examples)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('markdown', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.markdown.read_text(encoding='utf-8'),
                           json.loads(args.evidence.read_text(encoding='utf-8')))))
