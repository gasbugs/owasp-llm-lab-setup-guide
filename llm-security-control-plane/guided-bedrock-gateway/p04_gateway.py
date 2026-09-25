"""P04 Gateway wiring; startup and contract execution never create SDK clients."""
import hashlib
import importlib.util
from pathlib import Path

from p04_api import create_app
from p04_backend import BedrockBackend
from p04_contract import canonical
from p04_fixture_backend import ContractBackend
from p04_invocation import Invocation
from p04_ledger import GuardrailLedger, LedgerError
from p04_preparation import PreparationStore
from p04_provisioning import Provisioner
from p04_policy_audit import PolicyAudit
from p04_suites import SuiteStore, resource_snapshot


def load_cases():
    path = Path(__file__).with_name("p04_cases.py")
    if not path.is_file():
        path = Path(__file__).parents[1] / "guided-labs/h04-bedrock-guardrail/cases.py"
    spec = importlib.util.spec_from_file_location("p04_gateway_owned_cases", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.cases()


def configured_app(database_path, *, provider_mode, control_token, verifier_token,
                   region, prepared_resources=None, provision_token=None, policy_auditor=None):
    if provider_mode not in ("aws", "contract") or region != "us-east-1":
        raise ValueError("explicit P04 provider mode and course region required")
    if prepared_resources is not None and not callable(prepared_resources):
        raise ValueError("server-owned prepared-resource reader required")
    if policy_auditor is not None and not callable(policy_auditor):
        raise ValueError("server-owned policy auditor required")
    auditor = policy_auditor or PolicyAudit()
    ledger = GuardrailLedger(database_path)
    preparation = None
    if provision_token is not None and provider_mode == "aws":
        if prepared_resources is not None:
            raise ValueError("P04 preparation journal owns the resource reader")
        journal = PreparationStore(database_path)
        preparation = Provisioner(journal, region=region)
        prepared_resources = journal.resources

    def resources():
        if provider_mode == "contract":
            return {"provider_mode": "contract", "guardrail": {
                "guardrailIdentifier": "p04contract", "guardrailVersion": "DRAFT"}, "guardrail_arn": None,
                "policy_digest": hashlib.sha256(canonical({"fixture": "p04-email-output-v1"})).hexdigest()}
        if prepared_resources is None:
            raise LedgerError(409)
        snapshot = resource_snapshot(prepared_resources())
        if snapshot["provider_mode"] != "aws":
            raise LedgerError(409)
        return snapshot

    store = SuiteStore(database_path, load_cases(), resources)

    def invocation_for(suite, execution):
        # API capability authentication occurs before this factory; Invocation
        # validates/reserves the exact call before invoking either backend.
        def backend(operation, payload):
            row = store.lookup(suite, execution)
            case, snapshot = row["case"], row["resources"]
            if case["backend"] == "provider" and snapshot["provider_mode"] == "aws":
                invoke = BedrockBackend(case["body"], snapshot["guardrail"], region=region)
            else:
                invoke = ContractBackend(case, snapshot["guardrail"])
            return invoke(operation, payload)
        row = store.lookup(suite, execution)
        audit = (lambda: auditor(resources())) if (row['case']['backend'] == 'provider'
                  and row['resources']['provider_mode'] == 'aws') else None
        return Invocation(ledger, backend, lambda: store.resolve(suite, execution)["resource_digest"],
                          policy_audit=audit)

    return create_app(ledger, control_token=control_token, verifier_token=verifier_token,
                      invocation_for=invocation_for, suite_store=store,
                      provision_token=provision_token, preparation=preparation, resource_audit=auditor)
