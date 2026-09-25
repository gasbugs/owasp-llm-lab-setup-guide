"""Publisher AWS preparation/product smoke test, not learner or Browser grading.

Run in a temporary Gateway container. Preserve evidence and partial resources;
automatically remove only a successfully created, unchanged test guardrail.
"""
import argparse
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import boto3

from cases import cases
from p04_aws_cleanup import cleanup_created
from p04_aws_scope import preflight
from p04_backend import BedrockBackend
from p04_contract import expected_arguments
from p04_ledger import GuardrailLedger
from p04_policy_audit import PolicyAudit
from p04_preparation import PreparationStore
from p04_product import verify_product_response
from p04_provisioning import Provisioner


def run(account_id, output):
    output = Path(output)
    output.mkdir(exist_ok=False)
    database = output / 'preparation.sqlite3'
    operation = str(uuid4())
    proof = {'scope': 'actual AWS preparation and product adapter; not Practice completion',
             'operation_id': operation, 'checked': False, 'cases': [], 'aws_calls': []}

    def save(name, value):
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

    def observe(model, parsed, **kwargs):
        meta = parsed.get('ResponseMetadata', {})
        proof['aws_calls'].append({'operation': model.name, 'status': meta.get('HTTPStatusCode'),
            'request_id': meta.get('RequestId'), 'error_code': parsed.get('Error', {}).get('Code')})

    def factory(service, **kwargs):
        sdk = boto3.client(service, **kwargs)
        sdk.meta.events.register('after-call.*.*', observe)
        return sdk

    before = prepared = None
    try:
        before = preflight(account_id, client_factory=factory)
        save('preflight.json', before)
        proof['module_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ('/app', '/publisher', '/verifier')
            for path in Path(directory).glob('p04_*.py')}
        GuardrailLedger(database)
        store = PreparationStore(database)
        prepared = Provisioner(store, client_factory=factory).prepare(operation)
        save('prepared.json', prepared)
        resources = prepared['resources']
        policy = resources['guardrail']
        audit = PolicyAudit(client_factory=factory)
        for case in cases():
            if case['backend'] != 'provider':
                continue
            case_id = case['case_id']
            save(case_id + '-before.json', audit(resources))
            arguments = expected_arguments(case['body'], policy)
            response = BedrockBackend(case['body'], policy, client_factory=factory)(
                case['body']['operation'], arguments)
            save(case_id + '-response.json', response)
            save(case_id + '-after.json', audit(resources))
            result = verify_product_response(case, response, policy)
            proof['cases'].append({'case_id': case_id, **result})
        proof['checked'] = len(proof['cases']) == 4
    except Exception as error:
        proof['error_type'] = type(error).__name__
        raise
    finally:
        try:
            if prepared is not None:
                proof['cleanup'] = cleanup_created(before, prepared, database, client_factory=factory)
        except Exception as error:
            proof['cleanup_error_type'] = type(error).__name__
            raise
        finally:
            save('result.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-id', required=True)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.account_id, args.output_dir)
    print(json.dumps({'checked': result['checked'], 'product_cases': len(result['cases']),
                      'resources_absent': result['cleanup']['resources_absent']}))


if __name__ == '__main__':
    main()
