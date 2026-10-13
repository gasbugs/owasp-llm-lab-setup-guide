"""Configure P02 under the existing credential-owning Gateway without provisioning."""
import boto3
from botocore.config import Config

from p02_api import create_app
from p02_contract import ContractSDK
from p02_ledger import DocumentLedger, LedgerError
from p02_provider import DocumentProvider
from p02_resources import connection_evidence


def configured_app(state_loader, database_path, *, provider_mode, control_token, verifier_token, region):
    if provider_mode not in {"aws", "contract"}:
        raise ValueError("explicit P02 provider mode required")
    ledger = DocumentLedger(database_path)

    def provider():
        state = state_loader()
        if (not isinstance(state, dict) or state.get("status") != "READY" or state.get("provider_mode") != provider_mode
                or state.get("region") != region or state.get("source_prefix") != "h02/knowledge/"
                or not isinstance(state.get("source_bucket"), str) or not state["source_bucket"]):
            raise LedgerError(409)
        if provider_mode == "contract":
            s3 = runtime = ContractSDK(database_path)
        else:
            config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1, "mode": "standard"})
            s3 = boto3.client("s3", region_name=region, config=config)
            runtime = boto3.client("bedrock-runtime", region_name=region, config=config)
        return DocumentProvider(ledger, s3, runtime, state["source_bucket"], provider_mode=provider_mode)

    def resources():
        config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1, "mode": "standard"})
        return connection_evidence(state_loader(), mode=provider_mode,
                                   client_factory=lambda name: boto3.client(name, region_name=region, config=config))

    def native_credentials(execution_id):
        import json
        current = provider()
        if provider_mode == "contract":
            return {"provider_mode": "contract", "region": region, "bucket": current.bucket,
                "credentials": {"AccessKeyId": "contract-fixture-key", "SecretAccessKey": "contract-fixture-secret",
                                "SessionToken": "contract-fixture-session"}}
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:PutObject",
             "Resource": f"arn:aws:s3:::{current.bucket}/h02/knowledge/{execution_id}.md"},
            {"Effect": "Allow", "Action": "bedrock:InvokeModel",
             "Resource": f"arn:aws:bedrock:{region}::foundation-model/amazon.titan-embed-text-v2:0"}]}
        try:
            config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
            sts = boto3.client("sts", region_name=region, config=config)
            try:
                result = sts.get_federation_token(Name="p02-" + execution_id[:24],
                    DurationSeconds=900, Policy=json.dumps(policy, separators=(",", ":")))
            finally:
                sts.close()
            credentials = result["Credentials"]
            return {"provider_mode": "aws", "region": region, "bucket": current.bucket,
                "credentials": {key: credentials[key] for key in
                    ("AccessKeyId", "SecretAccessKey", "SessionToken")}}
        except Exception:
            raise LedgerError(502) from None

    return create_app(ledger, provider, native_credentials=native_credentials, control_token=control_token, verifier_token=verifier_token, resource_reader=resources)
