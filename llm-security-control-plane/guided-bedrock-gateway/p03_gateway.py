"""P03 deployment wiring; startup and suite registration never provision AWS."""
import importlib.util
from pathlib import Path
import sqlite3

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

    def provision(operation_id):
        if provider_mode != "aws":
            raise LedgerError(409)
        try:
            config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
            identity = boto3.client("sts", region_name=region, config=config).get_caller_identity()
            if identity["ResponseMetadata"]["HTTPStatusCode"] != 200 or not identity["ResponseMetadata"]["RequestId"]:
                raise ValueError()
            return prepare_aws(database_path, operation_id, identity["Account"])
        except LedgerError:
            raise
        except Exception:
            raise LedgerError(502) from None

    return create_app(
        ledger, lambda: SearchProvider(ledger, backend),
        control_token=control_token, verifier_token=verifier_token,
        job_resolver=store.resolve, suite_preparer=store.prepare,
        suite_reader=store.read, suite_resources=store.inspect_resources,
        provision_token=provision_token, resource_preparer=provision, preparation_reader=preparation.read,
    )
