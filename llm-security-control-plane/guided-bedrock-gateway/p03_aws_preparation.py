"""Explicit preparation coordinator. Never called from health or suite lookup."""
import boto3
from botocore.config import Config

from p03_create_resources import prepare_resources
from p03_seed_document import prepare_document
from p03_preparation import PreparationStore
from p03_ledger import LedgerError


def clients(region):
    config = Config(connect_timeout=5, read_timeout=20,
                    retries={"total_max_attempts": 1, "mode": "standard"})
    return {name: boto3.client(service, region_name=region, config=config)
            for name, service in (("sts", "sts"), ("s3", "s3"), ("vectors", "s3vectors"),
                                  ("iam", "iam"), ("agent", "bedrock-agent"))}


def prepare_aws(path, operation_id, account_id, *, client_factory=clients):
    store = PreparationStore(path)
    specification = store.begin(operation_id, account_id)
    try:
        sdk = client_factory(specification["region"])
        connection = prepare_resources(specification, operation_id, **sdk)
        document = prepare_document(specification, connection, operation_id,
                                    s3=sdk["s3"], agent=sdk["agent"])
        evidence = {"connection": connection, "document": document["evidence"]}
        store.publish(operation_id, document["snapshot"], evidence=evidence)
    except Exception:
        store.fail(operation_id)
        raise LedgerError(502) from None
    return store.read(operation_id)
