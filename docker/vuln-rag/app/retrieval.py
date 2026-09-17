"""Shared embedding ranking; callers own authorization and corpus selection."""
from __future__ import annotations

import math
from typing import Protocol, Sequence


class EmbeddingBackend(Protocol):
    model: str

    async def embed(self, inputs: Sequence[str]) -> list[list[float]]: ...


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise ValueError("embedding vectors must have equal non-zero dimensions")
    if any(not math.isfinite(value) for value in (*left, *right)):
        raise ValueError("embedding vectors must be finite")
    a, b = math.hypot(*left), math.hypot(*right)
    if not a or not b:
        raise ValueError("embedding vectors must have non-zero norms")
    return max(-1.0, min(1.0, sum((x / a) * (y / b) for x, y in zip(left, right))))


async def rank_texts(query, texts, backend, *, top_k=5, min_score=-1.0):
    """Rank only prefiltered candidates, with stable ties and validated vectors."""
    if not query.strip() or top_k < 1 or not -1 <= min_score <= 1:
        raise ValueError("invalid search parameters")
    if not texts:
        return 0, []
    vectors = await backend.embed([query, *texts])
    if len(vectors) != len(texts) + 1:
        raise ValueError("embedding backend returned an incomplete batch")
    cosine_similarity(vectors[0], vectors[0])
    scores = [(cosine_similarity(vectors[0], vector), index)
              for index, vector in enumerate(vectors[1:])]
    return len(vectors[0]), sorted(
        (item for item in scores if item[0] >= min_score),
        key=lambda item: (-item[0], item[1]),
    )[:top_k]


async def search_corpus(query, documents, backend, *, top_k=5, min_score=0.0):
    """Chunk an immutable corpus snapshot and return the exact generation context."""
    chunks = []
    for document_index, text in enumerate(documents):
        for offset in range(0, len(text), 700):
            chunks.append({"document_id": f"document-{document_index + 1}",
                           "chunk_id": f"{document_index + 1}:{offset}",
                           "text": text[offset:offset + 800]})
            if offset + 800 >= len(text):
                break
    dimensions, ranked = await rank_texts(
        query, [chunk["text"] for chunk in chunks], backend,
        top_k=top_k, min_score=min_score,
    )
    hits = [{**chunks[index], "rank": rank, "score": round(score, 8)}
            for rank, (score, index) in enumerate(ranked, 1)]
    return {"engine": "ollama-embedding-cosine", "model": backend.model,
            "dimensions": dimensions, "candidate_count": len(chunks),
            "top_k": top_k, "min_score": min_score, "hits": hits,
            "retrieved_chunks": [hit["text"] for hit in hits]}
