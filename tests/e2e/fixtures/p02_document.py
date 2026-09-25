"""Publisher-only reference implementation, never copied into the Starter image."""


async def prepare_document(body, document_id, services):
    if not isinstance(body, dict) or set(body) != {"title", "body"}:
        raise ValueError("title and body required")
    title, text = body["title"], body["body"]
    if (not isinstance(title, str) or not 1 <= len(title) <= 120
            or not title.strip() or "\n" in title or "\r" in title):
        raise ValueError("invalid title")
    if not isinstance(text, str) or not 10 <= len(text) <= 4000 or not text.strip():
        raise ValueError("invalid body")
    stored = await services.store_source(f"h02/knowledge/{document_id}.md", f"# {title}\n\n{text}\n")
    embedded = await services.embed(text)
    return {"source": stored, "embedding": embedded}
