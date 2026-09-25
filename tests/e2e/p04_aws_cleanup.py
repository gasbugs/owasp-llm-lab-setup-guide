"""Delete only one successfully created publisher-owned P04 test guardrail.

The caller must stop test writers first. This is not a distributed lock against
concurrent AWS administrators. No partial-run cleanup or name-based deletion.
"""
from contextlib import ExitStack
from datetime import datetime
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from p04_cleanup_proof import require, validate_local_ownership
from p04_resource_contract import template, validate_owned


def cleanup_created(before, prepared, database, *, client_factory=None,
                    now=time.time, clock=time.monotonic, sleep=time.sleep):
    proof = validate_local_ownership(before, prepared, database, now=now)
    specification = template(proof['account_id'])
    snapshot = proof['resources']
    guardrail_id = snapshot['guardrail']['guardrailIdentifier']
    params = {'guardrailIdentifier': guardrail_id, 'guardrailVersion': 'DRAFT'}
    deadline, ids = clock() + 90, []
    factory = client_factory or boto3.client

    def response(value, statuses=(200,)):
        require(clock() < deadline)
        meta = value['ResponseMetadata']
        request_id = meta['RequestId']
        require(type(meta['HTTPStatusCode']) is int and meta['HTTPStatusCode'] in statuses)
        require(isinstance(request_id, str) and request_id.isascii() and 1 <= len(request_id) <= 256
                and request_id not in ids)
        ids.append(request_id)
        return value

    def timestamps(detail):
        for key in ('createdAt', 'updatedAt'):
            value = detail[key]
            require(isinstance(value, datetime) and value.tzinfo is not None)
            # AWS timestamps have independent clock/precision; permit five seconds.
            require(proof['preparation_started_at'] - 5 <= value.timestamp()
                    <= proof['preparation_finished_at'] + 5)

    with ExitStack() as cleanup:
        def client(service):
            require(clock() < deadline)
            sdk = factory(service, region_name='us-east-1', config=Config(
                connect_timeout=3, read_timeout=10, retries={'total_max_attempts': 1}))
            cleanup.callback(sdk.close)
            return sdk
        identity = response(client('sts').get_caller_identity())
        require(identity['Account'] == proof['account_id'])
        bedrock = client('bedrock')
        detail = response(bedrock.get_guardrail(**params))
        tags = response(bedrock.list_tags_for_resource(resourceARN=snapshot['guardrail_arn']))['tags']
        require(validate_owned(specification, detail, tags, expected_id=guardrail_id) == snapshot)
        require({row['key']: row['value'] for row in tags} == specification['tags'])
        timestamps(detail)
        versions = response(bedrock.list_guardrails(guardrailIdentifier=guardrail_id, maxResults=100))
        require('nextToken' not in versions and len(versions['guardrails']) == 1)
        summary = versions['guardrails'][0]
        require(summary['id'] == guardrail_id and summary['arn'] == snapshot['guardrail_arn']
                and summary['name'] == specification['name'] and summary['version'] == 'DRAFT'
                and summary['status'] == 'READY')
        timestamps(summary)
        validate_local_ownership(before, prepared, database, now=now)
        require(clock() < deadline)
        # Omitting guardrailVersion deletes this exact guardrail, not another name.
        response(bedrock.delete_guardrail(guardrailIdentifier=guardrail_id), (200, 202, 204))
        for _ in range(30):
            require(clock() < deadline)
            try:
                response(bedrock.get_guardrail(**params))
            except ClientError as error:
                require(error.response['Error']['Code'] == 'ResourceNotFoundException')
                response(error.response, (404,))
                return {'operation_id': proof['operation_id'], 'guardrail_id': guardrail_id,
                        'resources_absent': True, 'aws_request_ids': ids}
            sleep(1)
        raise TimeoutError('P04 test guardrail deletion was not confirmed')
