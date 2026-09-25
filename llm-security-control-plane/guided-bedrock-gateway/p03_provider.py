"""Record P03 attempts around a server-configured status/retrieval backend."""
import hashlib
from uuid import uuid4

from p03_ledger import LedgerError


class SearchProvider:
    def __init__(self, ledger, backend):
        self.ledger, self.backend = ledger, backend

    def invoke(self, token, suite_id, execution_id, operation, payload):
        if type(payload) is not dict or payload:
            raise LedgerError(422)
        self.ledger.reserve(token, suite_id, execution_id, operation,
                            hashlib.sha256(b"{}").hexdigest())
        try:
            job = self.ledger.read(execution_id)["current_job_id"]
            method = {"job_status": self.backend.job_status,
                      "retrieve": self.backend.retrieve}[operation]
            native = method(job)
            if not isinstance(native, dict) or "observation_id" in native:
                raise LedgerError(502)
            response = {**native, "observation_id": str(uuid4())}
            self.ledger.finish(execution_id, operation, response)
            return response
        except Exception:
            try:
                self.ledger.finish(execution_id, operation)
            except LedgerError:
                pass
            raise LedgerError(502) from None
