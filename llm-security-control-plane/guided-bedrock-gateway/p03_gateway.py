"""P03 deployment wiring; startup and suite registration never provision AWS."""
import importlib.util
from pathlib import Path
import sqlite3
from resource_progress import tracked, step

import boto3
from botocore.config import Config

from p03_api import create_app
from p03_ledger import LedgerError, SearchLedger
from p03_provider import SearchProvider
from p03_preparation import PreparationStore
from p03_aws_preparation import prepare_aws
from p03_suites import CONTRACT_URI, RegisteredBackend, SuiteStore, bedrock_factory, resource_snapshot


def load_cases():
    path = Path(__file__).with_name("p03_cases.py")
    if not path.is_file():
        path = Path(__file__).parents[1] / "guided-labs/h03-ingestion-search/cases.py"
    spec = importlib.util.spec_from_file_location("p03_gateway_cases", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.cases()


def configured_app(database_path, *, provider_mode, control_token, verifier_token, region, provision_token=None):
    if provider_mode not in {"aws", "contract"} or region != "us-east-1":
        raise ValueError("explicit P03 provider mode and course region required")
    ledger = SearchLedger(database_path)
    preparation = PreparationStore(database_path)

    def resources():
        if provider_mode == "contract":
            return {"provider_mode": "contract", "binding": None, "source_uris": [CONTRACT_URI]}
        try:
            snapshot = preparation.resources()
            if snapshot["provider_mode"] != "aws" or snapshot["binding"]["region"] != region:
                raise ValueError()
            return snapshot
        except (sqlite3.Error, TypeError, ValueError, KeyError, LedgerError):
            raise LedgerError(409) from None

    store = SuiteStore(database_path, load_cases(), resources)

    def native(resources, job):
        config = Config(connect_timeout=5, read_timeout=20,
                        retries={"total_max_attempts": 1, "mode": "standard"})
        agent = boto3.client("bedrock-agent", region_name=region, config=config)
        runtime = boto3.client("bedrock-agent-runtime", region_name=region, config=config)
        return bedrock_factory(store, agent, runtime)(resources, job)

    backend = RegisteredBackend(store, native)

    @tracked("P03")
    def provision(operation_id):
        if provider_mode != "aws":
            raise LedgerError(409)
        try:
            step(1)
            config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
            identity = boto3.client("sts", region_name=region, config=config).get_caller_identity()
            if identity["ResponseMetadata"]["HTTPStatusCode"] != 200 or not identity["ResponseMetadata"]["RequestId"]:
                raise ValueError()
            return prepare_aws(database_path, operation_id, identity["Account"])
        except LedgerError:
            raise
        except Exception:
            raise LedgerError(502) from None

    def native_credentials(suite_id, execution_id):
        import json
        row = store.lookup(suite_id=suite_id, execution_id=execution_id)
        job = row['current_job_id']
        if row['case']['backend'] == 'contract' or provider_mode == 'contract':
            return {'provider_mode': 'contract', 'region': region, 'current_job_id': job,
                'binding': {'knowledgeBaseId': 'CONTRACTKB', 'dataSourceId': 'CONTRACTDS', 'ingestionJobId': job},
                'credentials': {'AccessKeyId': 'contract-fixture-key', 'SecretAccessKey': 'contract-fixture-secret', 'SessionToken': 'contract-fixture-session'}}
        snapshot = store.current_resources(row['resources'])
        binding = snapshot['binding']
        config = Config(connect_timeout=5, read_timeout=20, retries={'total_max_attempts': 1})
        sts = boto3.client('sts', region_name=region, config=config)
        try:
            account = sts.get_caller_identity()['Account']
            policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                'Action': ['bedrock:GetIngestionJob', 'bedrock:Retrieve'],
                'Resource': f"arn:aws:bedrock:{region}:{account}:knowledge-base/{binding['knowledge_base_id']}"}]}
            credentials = sts.get_federation_token(Name='p03-'+execution_id[:24], DurationSeconds=900,
                Policy=json.dumps(policy, separators=(',', ':')))['Credentials']
            return {'provider_mode': 'aws', 'region': region, 'current_job_id': job,
                'binding': {'knowledgeBaseId': binding['knowledge_base_id'], 'dataSourceId': binding['data_source_id'],
                            'ingestionJobId': binding['provider_ingestion_job_id']},
                'credentials': {k: credentials[k] for k in ('AccessKeyId', 'SecretAccessKey', 'SessionToken')}}
        except Exception: raise LedgerError(502) from None
        finally: sts.close()

    def native_recorder(suite_id, execution_id, capability, operation, response):
        import hashlib
        from copy import deepcopy
        ledger.reserve(capability, suite_id, execution_id, operation, hashlib.sha256(b'{}').hexdigest())
        try:
            if response is not None:
                response = deepcopy(response)
                row = store.lookup(suite_id=suite_id, execution_id=execution_id)
                binding = row['resources']['binding']
                if (response.get('provider_mode') != 'aws' or response.get('ingestion_job_id') != row['current_job_id']
                        or response.get('provider_ingestion_job_id') != binding['provider_ingestion_job_id']
                        or response.get('knowledge_base_id') != binding['knowledge_base_id']
                        or response.get('data_source_id') != binding['data_source_id']): raise LedgerError(502)
                if operation == 'retrieve':
                    response['status_observation'] = backend.job_status(row['current_job_id'])
            ledger.finish(execution_id, operation, response)
            return response
        except Exception:
            ledger.finish(execution_id, operation)
            raise LedgerError(502) from None

    return create_app(
        ledger, lambda: SearchProvider(ledger, backend), native_credentials=native_credentials, native_recorder=native_recorder,
        control_token=control_token, verifier_token=verifier_token,
        job_resolver=store.resolve, suite_preparer=store.prepare,
        suite_reader=store.read, suite_resources=store.inspect_resources,
        provision_token=provision_token, resource_preparer=provision, preparation_reader=preparation.read,
    )
