"""Create only absent P04 resources; never update, delete, or silently repair policies."""
from contextlib import ExitStack
import hashlib
import re
import threading
import time

import boto3
from botocore.config import Config

from p04_contract import canonical
from p04_ledger import LedgerError, identifier
from p04_resource_contract import inspect_existing, require, validate_owned


class Provisioner:
    def __init__(self, store, *, region='us-east-1', client_factory=None,
                 clock=time.monotonic, sleep=time.sleep):
        if region != 'us-east-1':
            raise ValueError('P04 requires the course region')
        self.store, self.region = store, region
        self.client_factory = client_factory or boto3.client
        self.clock, self.sleep = clock, sleep
        self.lock = threading.Lock()

    def read(self, operation_id):
        return self.store.read(operation_id)

    def prepare(self, operation_id):
        identifier(operation_id)
        if not self.lock.acquire(blocking=False):
            raise LedgerError(409)
        begun = False
        deadline = self.clock() + 270
        request_ids = []

        def check_time():
            require(self.clock() < deadline)

        def call(method, *, creation=False, **kwargs):
            check_time()
            result = method(**kwargs)
            check_time()
            metadata = result['ResponseMetadata']
            request_id = metadata['RequestId']
            require(type(metadata['HTTPStatusCode']) is int
                    and metadata['HTTPStatusCode'] in ((200, 201, 202) if creation else (200,))
                    and isinstance(request_id, str) and request_id.isascii() and 1 <= len(request_id) <= 256
                    and request_id not in request_ids)
            request_ids.append(request_id)
            return result

        try:
            previous_account = self.store.account()
            if previous_account is not None:
                specification = self.store.begin(operation_id, previous_account)
                begun = True
            with ExitStack() as stack:
                config = Config(connect_timeout=3, read_timeout=10, retries={'total_max_attempts': 1})

                def client(service):
                    check_time()
                    value = self.client_factory(service, region_name=self.region, config=config)
                    stack.callback(value.close)
                    return value

                identity = call(client('sts').get_caller_identity)
                account = identity['Account']
                require(isinstance(account, str) and re.fullmatch(r'[0-9]{12}', account))
                if previous_account is not None:
                    require(account == previous_account)
                else:
                    specification = self.store.begin(operation_id, account)
                    begun = True
                bedrock = client('bedrock')
                existing = inspect_existing(specification, client=bedrock, clock=self.clock)
                check_time()
                require(not set(request_ids).intersection(existing['aws_request_ids']))
                request_ids.extend(existing['aws_request_ids'])
                created = existing['state'] == 'absent'
                if not created:
                    snapshot = existing['resources']
                else:
                    response = call(bedrock.create_guardrail, creation=True,
                        name=specification['name'], description=specification['description'],
                        **specification['policy'],
                        tags=[{'key': key, 'value': value} for key, value in specification['tags'].items()],
                        clientRequestToken=hashlib.sha256(canonical({
                            'operation_id': operation_id, 'name': specification['name'],
                            'template_digest': specification['template_digest']})).hexdigest())
                    guardrail_id = response['guardrailId']
                    require(isinstance(guardrail_id, str) and re.fullmatch(r'[a-z0-9]{1,64}', guardrail_id))
                    arn = f'arn:aws:bedrock:{self.region}:{account}:guardrail/{guardrail_id}'
                    require(response['guardrailArn'] == arn and response['version'] == 'DRAFT')
                    for attempt in range(40):
                        detail = call(bedrock.get_guardrail, guardrailIdentifier=guardrail_id, guardrailVersion='DRAFT')
                        if detail.get('status') == 'READY':
                            break
                        require(detail.get('status') == 'CREATING' and attempt < 39)
                        self.sleep(2)
                    tags = call(bedrock.list_tags_for_resource, resourceARN=arn)
                    snapshot = validate_owned(specification, detail, tags['tags'], expected_id=guardrail_id)
                check_time()
                return self.store.publish(operation_id, snapshot,
                    {'aws_request_ids': request_ids, 'created': created})
        except Exception as error:
            if begun:
                self.store.fail(operation_id)
            if isinstance(error, LedgerError):
                raise
            raise LedgerError(502) from None
        finally:
            self.lock.release()
