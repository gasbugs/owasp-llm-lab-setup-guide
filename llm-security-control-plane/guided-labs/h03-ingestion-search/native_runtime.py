"""Observe learner-owned Boto3 calls; contract fixtures remain explicitly synthetic."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import date, datetime
import hashlib
import json
from unittest.mock import patch
from uuid import uuid4

import boto3
from botocore.client import BaseClient
import httpx
from service_client import ServiceClient, ServiceError


def serial(value):
    return json.loads(json.dumps(value, default=lambda x: x.isoformat() if isinstance(x, (date, datetime)) else None))


class NativeSDK(ServiceClient):
    def __init__(self, query='GUIDED-H03-ORION access procedure', **configuration):
        if not isinstance(query, str) or not query.strip() or len(query) > 1000:
            raise ValueError('invalid search query')
        self.query = query
        super().__init__(**configuration)
        self.connection = None
        self.clients = []
        self.native = {}
        self.proofs = {}

    def authenticate(self):
        if self.connection is None:
            with httpx.Client(timeout=25, follow_redirects=False, trust_env=False) as client:
                response = client.post(self.origin + '/v1/p03/native-credentials',
                    headers={'Authorization': 'Bearer ' + self.capability},
                    json={'suite_id': self.suite_id, 'execution_id': self.execution_id})
                if response.status_code != 200 or len(response.content) > 16384:
                    raise ServiceError('P03 AWS authentication unavailable')
                self.connection = response.json()
            if (self.connection.get('region') != 'us-east-1'
                    or self.connection.get('provider_mode') not in {'aws', 'contract'}):
                raise ServiceError('P03 AWS authentication binding invalid')
        return self.connection

    @contextmanager
    def observe(self):
        factory = boto3.session.Session.client
        opened = []
        def client(session, name, **kwargs):
            connection = self.authenticate()
            allowed = {'bedrock-agent', 'bedrock-agent-runtime'}
            if name not in allowed or set(kwargs) != {'region_name', 'config'} or kwargs['region_name'] != 'us-east-1':
                raise ServiceError('P03 SDK client outside scope')
            config = kwargs['config']
            if (config.connect_timeout != 5 or config.read_timeout != 20
                    or config.retries.get('total_max_attempts') != 1
                    or name in {c['service'] for c in self.clients}):
                raise ServiceError('P03 SDK client configuration invalid')
            credentials = session.get_credentials().get_frozen_credentials()
            issued = connection['credentials']
            if (credentials.access_key, credentials.secret_key, credentials.token) != (
                    issued['AccessKeyId'], issued['SecretAccessKey'], issued['SessionToken']):
                raise ServiceError('P03 AWS credentials changed')
            value = factory(session, name, **kwargs)
            if not isinstance(value, BaseClient):
                raise ServiceError('P03 requires a real Boto3 client')
            original = value._make_api_call
            value._make_api_call = lambda operation, params: self.invoke(name, operation, params, original)
            opened.append(value)
            self.clients.append({'service': name, 'region': 'us-east-1', 'native_sdk': True})
            return value
        try:
            with patch.object(boto3.session.Session, 'client', client):
                yield
        finally:
            for value in opened:
                value.close()

    def invoke(self, service, operation, params, original):
        connection = self.authenticate()
        binding = connection['binding']
        status_params = {key: binding[key] for key in ('knowledgeBaseId', 'dataSourceId', 'ingestionJobId')}
        retrieval_params = {'knowledgeBaseId': binding['knowledgeBaseId'],
            'retrievalQuery': {'text': self.query},
            'retrievalConfiguration': {'vectorSearchConfiguration': {'numberOfResults': 3}}}
        if service == 'bedrock-agent' and operation == 'GetIngestionJob' and params == status_params and not self.calls:
            kind = 'job_status'
        elif (service == 'bedrock-agent-runtime' and operation == 'Retrieve' and params == retrieval_params
                and len(self.calls) == 1 and self.calls[0]['state'] == 'complete'
                and self.proofs['job_status'].get('status') == 'COMPLETE'
                and self.proofs['job_status'].get('ingestion_job_id') == connection['current_job_id']):
            kind = 'retrieve'
        else:
            raise ServiceError('P03 SDK call order or arguments invalid')
        if connection['provider_mode'] == 'contract':
            try:
                proof = self._invoke(kind, {})
            except ServiceError:
                self.calls[-1].update(native_sdk=True, sdk_service=service, sdk_operation=operation)
                raise
            if kind == 'job_status':
                job = {'knowledgeBaseId': binding['knowledgeBaseId'], 'dataSourceId': binding['dataSourceId']}
                if 'ingestion_job_id' in proof: job['ingestionJobId'] = proof['ingestion_job_id']
                if 'status' in proof: job['status'] = proof['status']
                raw = {'ingestionJob': job, 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': proof['observation_id']}}
            else:
                raw = {'retrievalResults': proof['results'], 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': proof['observation_id']}}
        else:
            call = {'operation': kind, 'state': 'error', 'request_digest': hashlib.sha256(b'{}').hexdigest(), 'http_status': 502}
            self.calls.append(call)
            try:
                raw = original(operation, params)
                metadata = raw['ResponseMetadata']
                if metadata['HTTPStatusCode'] != 200 or not metadata.get('RequestId'):
                    raise ValueError()
                identity = {'provider_mode': 'aws', 'ingestion_job_id': connection['current_job_id'],
                    'provider_ingestion_job_id': binding['ingestionJobId'], 'knowledge_base_id': binding['knowledgeBaseId'],
                    'data_source_id': binding['dataSourceId'], 'provider_request_id': metadata['RequestId'],
                    'observation_id': str(uuid4())}
                if kind == 'job_status':
                    job = raw['ingestionJob']
                    if any(job.get(k) != v for k,v in status_params.items()): raise ValueError()
                    proof = {**identity, 'status': job['status'], 'statistics': job.get('statistics', {})}
                else:
                    if raw.get('nextToken') or len(raw['retrievalResults']) > 3: raise ValueError()
                    proof = {**identity, 'results': raw['retrievalResults']}
                call.update(state='complete', http_status=200, response_digest=self.digest(proof), response=proof)
            except Exception:
                raise ServiceError('P03 native AWS call failed') from None
        self.calls[-1].update(native_sdk=True, sdk_service=service, sdk_operation=operation)
        self.native[kind] = serial(raw)
        self.proofs[kind] = deepcopy(proof)
        return raw

    @staticmethod
    def digest(value):
        return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()).hexdigest()

    def normalize(self, value):
        if value == {'status': 'waiting', 'result': None} and set(self.native) == {'job_status'}:
            return value
        if (isinstance(value, dict) and set(value) == {'status', 'result'} and value['status'] == 'ready'
                and self.digest(serial(value['result'])) == self.digest(self.native.get('retrieve'))):
            return {'status': 'ready', 'result': deepcopy(self.proofs['retrieve'])}
        raise ServiceError('P03 return must contain the actual SDK response')
