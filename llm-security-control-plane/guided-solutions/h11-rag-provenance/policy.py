"""H11 solution: only server-owned identity and provenance may filter RAG."""


def allowed_documents(principal: dict, documents: list[dict], client_claims: dict) -> list[dict]:
    # Browser claims are untrusted. Authentication and approval records own the filter.
    roles = set(principal["roles"])
    return [
        document
        for document in documents
        if document["tenant"] == principal["tenant"]
        and document["approval_status"] == "approved"
        and document["source_kind"] in {"reviewed-handbook"}
        and roles.intersection(document["allowed_roles"])
    ]
