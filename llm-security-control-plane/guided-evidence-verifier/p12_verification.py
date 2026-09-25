"""Read-only P12 product re-query; root receipt and problem contract are caller-owned."""
import asyncio
from contextlib import asynccontextmanager
import json
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from p12_results import validate_case, EvidenceError
from p12_binding import validate_run_binding


@asynccontextmanager
async def verified_run_snapshot(origin, token, *, suite_id, case_ids, contract_digest,
                                scaffold_files, now=None, transport=None):
    """Read-only root bracket. Consume results only after successful context exit.

    The caller checks downstream products inside this scope. Binding alone does
    not establish task completion, and cannot detect changes reverted between reads.
    """
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or not isinstance(token, str) or not token or not token.isascii()
                or str(UUID(suite_id)) != suite_id):
            raise EvidenceError("invalid runner verifier connection")
        async with asyncio.timeout(180), httpx.AsyncClient(timeout=5, follow_redirects=False,
                trust_env=False, transport=transport) as client:
            async def get(path, limit):
                async with client.stream("GET", origin.rstrip("/") + path,
                        headers={"Authorization": "Bearer " + token}) as response:
                    if response.status_code != 200:
                        raise EvidenceError("runner re-query failed")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > limit:
                            raise EvidenceError("runner evidence exceeds limit")
                return json.loads(raw)

            build = await get("/v1/build-info", 65536)
            path = f"/v1/receipts/{suite_id}"
            receipt = await get(path, 2 * 1024 * 1024)
            options = {"suite_id": suite_id, "case_ids": case_ids, "contract_digest": contract_digest,
                       "scaffold_files": scaffold_files}
            binding = validate_run_binding(receipt, build, now=time.time() if now is None else now, **options)
            # Keep private snapshots: caller mutation must not rewrite the comparison baseline.
            baseline = json.dumps({"receipt": receipt, "build": build}, sort_keys=True, allow_nan=False)
            yield {"receipt": receipt, "build_info": build, "binding": binding}
            current_receipt = await get(path, 2 * 1024 * 1024)
            current_build = await get("/v1/build-info", 65536)
            if json.dumps({"receipt": current_receipt, "build": current_build}, sort_keys=True, allow_nan=False) != baseline:
                raise EvidenceError("runner changed during verification")
            if json.dumps({"receipt": receipt, "build": build}, sort_keys=True, allow_nan=False) != baseline:
                raise EvidenceError("runner snapshot was modified")
            validate_run_binding(current_receipt, current_build, now=time.time() if now is None else now, **options)
    except EvidenceError:
        raise
    except Exception:
        raise EvidenceError("P12 runner evidence unavailable") from None


async def verify_case_from_services(attempt, origins, tokens, *, source_digest, expected_case, expected_status,
                                    expected_stop, now=None, transport=None):
    services = {"context", "privacy", "nemo", "gateway"}
    if set(origins) != services or set(tokens) != services:
        raise EvidenceError("dedicated verifier connections required")
    for service, origin in origins.items():
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or not isinstance(tokens[service], str) or not tokens[service] or not tokens[service].isascii()):
            raise EvidenceError("invalid verifier connection")
    try:
        suite = str(UUID(attempt["suite_id"]))
        async with asyncio.timeout(20), httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False, transport=transport) as client:
            async def get(service, path):
                async with client.stream("GET", origins[service].rstrip("/") + path,
                                         headers={"Authorization": "Bearer " + tokens[service]}) as response:
                    if response.status_code != 200:
                        raise EvidenceError("product re-query failed")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 262144:
                            raise EvidenceError("product evidence exceeds limit")
                return json.loads(raw)
            builds, ledgers = {}, {}
            for service in sorted(services):
                if service != "gateway":
                    builds[service] = await get(service, "/v1/build-info")
                prefix = "/v1/p12" if service == "gateway" else "/v1"
                ledgers[service] = await get(service, f"{prefix}/suites/{suite}/ledger")
            for service, build in builds.items():
                if await get(service, "/v1/build-info") != build:
                    raise EvidenceError("product changed during verification")
        result = validate_case(attempt, ledgers, builds, source_digest=source_digest,
                               expected_case=expected_case,
                               expected_status=expected_status, expected_stop=expected_stop,
                               now=time.time() if now is None else now)
        return {"consistency": result, "ledgers": ledgers, "service_builds": builds}
    except EvidenceError:
        raise
    except Exception:
        raise EvidenceError("P12 product evidence unavailable") from None
