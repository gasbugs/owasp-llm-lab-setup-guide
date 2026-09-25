"""Trusted P04 call coordinator; records calls without assigning a verdict."""
from p04_contract import validate_invocation
from p04_ledger import LedgerError


class InvocationError(RuntimeError):
    pass


class Invocation:
    def __init__(self, ledger, backend, resource_digest, policy_audit=None):
        self.ledger, self.backend, self.resource_digest = ledger, backend, resource_digest
        self.policy_audit = policy_audit

    def invoke(self, token, suite_id, execution_id, operation, payload):
        self.ledger.reserve(token, suite_id, execution_id, operation, payload)
        try:
            registered = self.ledger.read(execution_id)
            arguments = validate_invocation(operation, payload, body=registered["body"],
                                            guardrail=registered["guardrail"])
            if self.resource_digest() != registered["resource_digest"]:
                raise ValueError("resource changed")
            if self.policy_audit is not None:
                self.ledger.policy_audit(execution_id, 'before', self.policy_audit())
            self.ledger.dispatch(execution_id)
            response = self.backend(operation, arguments)
            if not isinstance(response, dict):
                raise ValueError("provider returned no response object")
            if self.resource_digest() != registered["resource_digest"]:
                raise ValueError("resource changed")
            if self.policy_audit is not None:
                self.ledger.policy_audit(execution_id, 'after', self.policy_audit())
            self.ledger.finish(execution_id, response)
            return {"suite_id": suite_id, "execution_id": execution_id,
                    "operation": operation, "response": response}
        except Exception:
            try:
                self.ledger.finish(execution_id)
            except LedgerError:
                pass
            raise InvocationError("P04 provider invocation failed") from None
