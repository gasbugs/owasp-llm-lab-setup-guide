#!/usr/bin/env python3
"""Learner-built LLM08 mini app: same embeddings, different filter placement.

This is deliberately small training code, not a production vector database.
It uses only the Python standard library and delegates embedding generation to
the canonical lab server's authenticated ``POST /api/embed`` endpoint.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Sequence


ENGINE = "learner-mini-in-memory-cosine"
AUTHENTICATED_TENANT = "acme"
MAX_QUERY_CHARS = 4096
MAX_BODY_BYTES = 64 * 1024
ALLOWED_BIND_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


@dataclass(frozen=True)
class Document:
    document_id: str
    tenant: str
    text: str


DOCUMENTS = (
    Document(
        "acme/q1.md",
        "acme",
        "ACME Q1 revenue: $1.2M. Top product: Anvil-X. Internal only.",
    ),
    Document(
        "acme/security.md",
        "acme",
        "ACME passcode for emergency reset: ACME-RESET-9921.",
    ),
    Document(
        "beta/launch.md",
        "beta",
        "Beta team plans to launch Phoenix project on 2026-07-01.",
    ),
    Document(
        "beta/api.md",
        "beta",
        "Beta team uses API key: bsk-test-aaaa-bbbb (rotating monthly).",
    ),
)


class InputError(ValueError):
    """The learner supplied an invalid request."""


class EmbeddingError(RuntimeError):
    """The canonical embedding endpoint failed or broke its contract."""


EmbeddingFunction = Callable[[Sequence[str]], tuple[str, list[list[float]]]]


def normalize_target_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise InputError("TARGET_URL must be a loopback HTTP origin")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise InputError("TARGET_URL contains an invalid port") from exc
    if parsed_port is None:
        raise InputError("TARGET_URL must include an explicit port")
    return value.rstrip("/")


class EmbeddingHTTPClient:
    def __init__(self, target_url: str, token: str, timeout: float = 120.0) -> None:
        self.target_url = normalize_target_url(target_url)
        if not token.strip():
            raise InputError("LLM08_TOKEN must not be empty")
        if timeout <= 0:
            raise InputError("embedding timeout must be positive")
        self.token = token
        self.timeout = timeout

    def embed(self, texts: Sequence[str]) -> tuple[str, list[list[float]]]:
        values = list(texts)
        if not values or any(not isinstance(value, str) or not value.strip() for value in values):
            raise InputError("embedding input must contain non-empty strings")
        body = json.dumps({"input": values}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.target_url}/api/embed",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise EmbeddingError(f"embedding endpoint returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise EmbeddingError("embedding endpoint is unavailable") from exc

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EmbeddingError("embedding endpoint returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise EmbeddingError("embedding response must be an object")

        model = payload.get("model")
        dimensions = payload.get("dimensions")
        vectors = payload.get("embeddings")
        if not isinstance(model, str) or not model:
            raise EmbeddingError("embedding response is missing model")
        if isinstance(dimensions, bool) or not isinstance(dimensions, int) or dimensions < 1:
            raise EmbeddingError("embedding response has invalid dimensions")
        if not isinstance(vectors, list) or len(vectors) != len(values):
            raise EmbeddingError("embedding response has an invalid batch")

        validated: list[list[float]] = []
        for vector in vectors:
            if not isinstance(vector, list) or len(vector) != dimensions:
                raise EmbeddingError("embedding vector dimension mismatch")
            converted: list[float] = []
            for value in vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise EmbeddingError("embedding vector contains a non-number")
                number = float(value)
                if not math.isfinite(number):
                    raise EmbeddingError("embedding vector contains a non-finite number")
                converted.append(number)
            validated.append(converted)
        return model, validated


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise EmbeddingError("cosine vectors must have equal non-zero dimensions")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        raise EmbeddingError("cosine vectors must have non-zero norms")
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


def semantic_search(
    query: str,
    mode: str,
    top_k: int,
    embed: EmbeddingFunction,
) -> dict[str, object]:
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
        raise InputError("query must contain 1 to 4096 characters")
    if mode not in {"vulnerable", "safe"}:
        raise InputError("mode must be vulnerable or safe")
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 4:
        raise InputError("top_k must be an integer from 1 to 4")

    # This is the line learners fix: safe mode narrows candidates BEFORE vectors
    # are generated and ranked. Vulnerable mode sends all tenants to retrieval.
    filter_applied = mode == "safe"
    candidates = [
        document
        for document in DOCUMENTS
        if not filter_applied or document.tenant == AUTHENTICATED_TENANT
    ]

    model, vectors = embed([query, *(document.text for document in candidates)])
    if len(vectors) != len(candidates) + 1:
        raise EmbeddingError("embedding function returned an incomplete batch")
    query_vector = vectors[0]
    dimensions = len(query_vector)
    ranked = sorted(
        (
            (cosine_similarity(query_vector, vector), document)
            for vector, document in zip(vectors[1:], candidates)
        ),
        key=lambda item: (-item[0], item[1].document_id),
    )[:top_k]

    return {
        "engine": ENGINE,
        "model": model,
        "dimensions": dimensions,
        "mode": mode,
        "authenticated_tenant": AUTHENTICATED_TENANT,
        "filter_applied": filter_applied,
        "candidate_count": len(candidates),
        "query": query,
        "hits": [
            {
                "rank": rank,
                "document_id": document.document_id,
                "tenant": document.tenant,
                "score": round(score, 8),
                "text": document.text,
            }
            for rank, (score, document) in enumerate(ranked, 1)
        ],
    }


class MiniVectorSearchApp:
    def __init__(self, embed: EmbeddingFunction) -> None:
        self.embed = embed

    def search_payload(self, payload: object) -> dict[str, object]:
        if not isinstance(payload, dict):
            raise InputError("request body must be a JSON object")
        unknown = set(payload) - {"query", "mode", "top_k"}
        if unknown:
            raise InputError(f"unknown request fields: {', '.join(sorted(unknown))}")
        return semantic_search(
            query=payload.get("query"),
            mode=payload.get("mode", "vulnerable"),
            top_k=payload.get("top_k", 2),
            embed=self.embed,
        )


INDEX_HTML = """<!doctype html>
<html lang="ko"><meta charset="utf-8"><title>LLM08 Mini Vector Search</title>
<style>body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}
input,select,button{font:inherit;padding:.5rem}input{width:65%}pre{background:#111;color:#eee;padding:1rem;overflow:auto}</style>
<h1>LLM08 Mini Vector Search</h1>
<p>같은 query와 embedding에서 tenant filter 위치만 비교합니다.</p>
<form id="f"><input id="q" value="경쟁 조직의 불사조 계획은 언제 실제 서비스에 투입되나요?">
<select id="m"><option>vulnerable</option><option>safe</option></select><button>검색</button></form>
<pre id="out">Run a search.</pre><script>
f.onsubmit=async(e)=>{e.preventDefault();let r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q.value,mode:m.value,top_k:2})});out.textContent=JSON.stringify(await r.json(),null,2)};
</script></html>"""


def make_handler(app: MiniVectorSearchApp):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
            path = urllib.parse.urlsplit(self.path).path
            if path == "/healthz":
                self.send_json(200, {"ok": True, "engine": ENGINE})
                return
            if path == "/":
                body = INDEX_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
            if urllib.parse.urlsplit(self.path).path != "/api/search":
                self.send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= MAX_BODY_BYTES:
                    raise InputError("request body size is invalid")
                payload = json.loads(self.rfile.read(length))
                result = app.search_payload(payload)
            except (InputError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.send_json(400, {"error": "invalid_request", "detail": str(exc)})
                return
            except EmbeddingError as exc:
                self.send_json(502, {"error": "embedding_unavailable", "detail": str(exc)})
                return
            self.send_json(200, result)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", help="semantic search query for CLI mode")
    parser.add_argument("--mode", choices=("vulnerable", "safe"), default="vulnerable")
    parser.add_argument("--top-k", type=int, default=2)
    parser.add_argument("--serve", action="store_true", help="serve HTML and POST /api/search")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="listen address: loopback (default) or explicit 0.0.0.0",
    )
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--target-url", default=os.environ.get("TARGET_URL", "http://localhost:8012"))
    parser.add_argument("--token", default=os.environ.get("LLM08_TOKEN", "llm08-acme-demo-token"))
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    if not args.serve and args.query is None:
        parser.error("--query is required unless --serve is used")
    if args.host not in ALLOWED_BIND_HOSTS:
        parser.error("--host must be a loopback address or 0.0.0.0")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be from 1 to 65535")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        client = EmbeddingHTTPClient(args.target_url, args.token, args.timeout)
        app = MiniVectorSearchApp(client.embed)
        if args.serve:
            if args.host == "0.0.0.0":
                print(
                    "WARNING: listening on every EC2 interface; "
                    f"restrict Security Group TCP port {args.port} to your public /32",
                    flush=True,
                )
            server = ThreadingHTTPServer((args.host, args.port), make_handler(app))
            local_check_host = "127.0.0.1" if args.host == "0.0.0.0" else args.host
            if local_check_host == "::1":
                local_check_host = "[::1]"
            print(f"listening bind={args.host}:{args.port}", flush=True)
            print(
                f"local check URL=http://{local_check_host}:{args.port}/healthz",
                flush=True,
            )
            print(f"embedding backend: {client.target_url}/api/embed", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0

        result = semantic_search(args.query, args.mode, args.top_k, client.embed)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (InputError, EmbeddingError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
