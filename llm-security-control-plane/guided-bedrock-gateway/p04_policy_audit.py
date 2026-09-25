"""Read-only current AWS policy audit; never a cached preparation success."""
from contextlib import ExitStack
import time

import boto3
from botocore.config import Config

from p04_ledger import LedgerError
from p04_resource_contract import require, template, validate_owned
from p04_suites import resource_snapshot


class PolicyAudit:
    def __init__(self, *, client_factory=None, clock=time.monotonic, now=time.time):
        self.client_factory = client_factory or boto3.client
        self.clock, self.now = clock, now

    def __call__(self, resources):
        snapshot = resource_snapshot(resources)
        require(snapshot['provider_mode'] == 'aws')
        account = snapshot['guardrail_arn'].split(':')[4]
        specification = template(account)
        require(snapshot['policy_digest'] == specification['template_digest'])
        started, deadline, ids = self.now(), self.clock() + 12, []
        try:
            with ExitStack() as stack:
                def client(service):
                    require(self.clock() < deadline)
                    result = self.client_factory(service, region_name='us-east-1',
                        config=Config(connect_timeout=1, read_timeout=3, retries={'total_max_attempts': 1}))
                    stack.callback(result.close)
                    return result

                def call(method, **kwargs):
                    require(self.clock() < deadline)
                    result = method(**kwargs)
                    require(self.clock() < deadline)
                    meta = result['ResponseMetadata']
                    request_id = meta['RequestId']
                    require(type(meta['HTTPStatusCode']) is int and meta['HTTPStatusCode'] == 200
                            and isinstance(request_id, str) and request_id.isascii() and 1 <= len(request_id) <= 256
                            and request_id not in ids)
                    ids.append(request_id)
                    return result

                identity = call(client('sts').get_caller_identity)
                require(identity['Account'] == account)
                bedrock = client('bedrock')
                detail = call(bedrock.get_guardrail, **snapshot['guardrail'])
                tags = call(bedrock.list_tags_for_resource, resourceARN=snapshot['guardrail_arn'])
                actual = validate_owned(specification, detail, tags['tags'],
                                        expected_id=snapshot['guardrail']['guardrailIdentifier'])
                require(actual == snapshot)
                finished = self.now()
                require(0 < started <= finished and finished - started < 12)
                return {'scope': 'aws-policy-audit', 'started_at': started, 'observed_at': finished,
                        'resources': actual, 'aws_request_ids': ids}
        except LedgerError:
            raise
        except Exception:
            raise LedgerError(502) from None
