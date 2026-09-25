"""Publisher-only read-only P04 absence preflight, run in the Gateway image.

A receipt proves absence at its observation time, not ownership of later
resources or authorization to delete them. Existing or uncertain state stops
the publisher. This module is never included in a learner or product image.
"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import time
from uuid import uuid4

import boto3
from botocore.config import Config

from p04_resource_contract import inspect_existing, require, template

READ_OPERATIONS = frozenset({'GetCallerIdentity', 'ListGuardrails', 'GetGuardrail', 'ListTagsForResource'})


class ReadOnlyCalls:
    def __init__(self):
        self.attempted, self.responses = [], []

    def before(self, model, **kwargs):
        if model.name not in READ_OPERATIONS:
            raise ValueError('P04 publisher preflight cannot write or invoke a model')
        self.attempted.append(model.name)

    def after(self, model, parsed, **kwargs):
        meta = parsed.get('ResponseMetadata', {})
        self.responses.append({'operation': model.name, 'status': meta.get('HTTPStatusCode'),
                               'request_id': meta.get('RequestId')})

    def attach(self, client):
        client.meta.events.register('before-call.*.*', self.before)
        client.meta.events.register('after-call.*.*', self.after)


def preflight(account_id, *, client_factory=None, now=time.time, clock=time.monotonic):
    specification = template(account_id)
    factory = client_factory or boto3.client
    started, deadline = now(), clock() + 90
    guard = ReadOnlyCalls()
    try:
        with ExitStack() as cleanup:
            def client(service):
                require(clock() < deadline)
                sdk = factory(service, region_name='us-east-1', config=Config(
                    connect_timeout=3, read_timeout=10, retries={'total_max_attempts': 1}))
                cleanup.callback(sdk.close)
                guard.attach(sdk)
                return sdk
            identity = client('sts').get_caller_identity()
            meta = identity['ResponseMetadata']
            request_id = meta['RequestId']
            require(identity['Account'] == account_id and type(meta['HTTPStatusCode']) is int
                    and meta['HTTPStatusCode'] == 200 and isinstance(request_id, str)
                    and request_id.isascii() and 1 <= len(request_id) <= 256)
            result = inspect_existing(specification, client=client('bedrock'), clock=clock)
            require(result['state'] == 'absent' and result['resources'] is None)
            ids = [request_id, *result['aws_request_ids']]
            require(len(set(ids)) == len(ids) and clock() < deadline)
            finished = now()
            require(0 < started <= finished and finished - started < 90)
            return {'scope': 'read-only P04 absence preflight; no creation or cleanup authorization',
                'preflight_id': str(uuid4()), 'account_id': account_id, 'region': 'us-east-1',
                'template_digest': specification['template_digest'], 'name': specification['name'],
                'started_at': started, 'finished_at': finished, 'resources_absent': True,
                'aws_request_ids': ids, 'attempted_operations': guard.attempted, 'responses': guard.responses}
    except Exception:
        raise ValueError('P04 preflight could not establish safe absent state') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('preserve existing evidence; choose another output')
    result = preflight(args.account_id)
    with args.output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'resources_absent': True, 'read_calls': len(result['responses']), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
