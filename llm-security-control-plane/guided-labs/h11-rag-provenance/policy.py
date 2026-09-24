"""Learner-owned H11 candidate filter. The starter trusts Browser claims."""


def allowed_documents(principal: dict, documents: list[dict], client_claims: dict) -> list[dict]:
    # 취약한 Starter: Browser가 적은 tenant와 roles를 서버 인증값보다 우선합니다.
    tenant = client_claims.get("tenant", principal["tenant"])
    roles = set(client_claims.get("roles", principal["roles"]))
    require_approved = client_claims.get("require_approved", True)
    return [
        document
        for document in documents
        if document["tenant"] == tenant
        and roles.intersection(document["allowed_roles"])
        and (not require_approved or document["approval_status"] == "approved")
    ]
