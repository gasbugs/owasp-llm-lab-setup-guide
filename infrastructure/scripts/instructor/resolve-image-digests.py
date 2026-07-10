#!/usr/bin/env python3
"""Resolve immutable public-registry manifests without exposing auth tokens.

The live-validation controller uses the tag digest as registry provenance and the
linux/amd64 child digest as the value that must be present in Podman storage on
the EC2 host. The registry's anonymous bearer token is kept in memory and is
never included in the emitted JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


IMAGES = ("base-gpu", "vuln-rag", "vuln-agent", "llmgoat", "dvla")
ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAMESPACE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
TAG_RE = re.compile(r"^sha-[0-9a-f]{40}$")
CANONICAL_REGISTRY = "ghcr.io"


class ResolutionError(RuntimeError):
    """A registry response violated the immutable-image contract."""


@dataclass(frozen=True)
class ManifestResponse:
    digest: str
    media_type: str
    body: bytes
    document: Mapping[str, Any]


def _parse_bearer_challenge(value: str) -> tuple[str, dict[str, str]]:
    scheme, separator, parameters = value.partition(" ")
    if separator != " " or scheme.lower() != "bearer":
        raise ResolutionError("registry did not return a Bearer challenge")
    parsed: dict[str, str] = {}
    for match in re.finditer(r'(\w+)="([^"]*)"(?:,\s*)?', parameters):
        parsed[match.group(1)] = match.group(2)
    realm = parsed.pop("realm", "")
    if not realm.startswith("https://"):
        raise ResolutionError("registry Bearer realm must use https")
    if "service" not in parsed or "scope" not in parsed:
        raise ResolutionError("registry Bearer challenge is incomplete")
    return realm, parsed


def _select_linux_amd64(document: Mapping[str, Any]) -> str:
    matches: list[str] = []
    manifests = document.get("manifests")
    if not isinstance(manifests, list):
        raise ResolutionError("image index has no manifests array")
    for item in manifests:
        if not isinstance(item, dict):
            continue
        platform = item.get("platform")
        if not isinstance(platform, dict):
            continue
        if platform.get("os") != "linux" or platform.get("architecture") != "amd64":
            continue
        # Attestations commonly use an unknown platform.  An explicit amd64
        # variant is not part of this course's runtime contract.
        if platform.get("variant") not in (None, ""):
            continue
        digest = item.get("digest")
        if isinstance(digest, str) and DIGEST_RE.fullmatch(digest):
            matches.append(digest)
    if len(matches) != 1:
        raise ResolutionError(
            f"expected exactly one linux/amd64 manifest, found {len(matches)}"
        )
    return matches[0]


class RegistryClient:
    def __init__(self, registry: str = CANONICAL_REGISTRY, timeout: int = 20) -> None:
        if registry != CANONICAL_REGISTRY:
            raise ResolutionError(f"registry must be {CANONICAL_REGISTRY}")
        self.registry = registry
        self.timeout = timeout
        self._tokens: dict[str, str] = {}

    def _open(self, request: urllib.request.Request):
        return urllib.request.urlopen(request, timeout=self.timeout)

    def _token_for(self, challenge: str) -> str:
        realm, parameters = _parse_bearer_challenge(challenge)
        cache_key = json.dumps([realm, parameters], sort_keys=True)
        if cache_key in self._tokens:
            return self._tokens[cache_key]
        token_url = f"{realm}?{urllib.parse.urlencode(parameters)}"
        request = urllib.request.Request(token_url, headers={"User-Agent": "owasp-llm-live-validator/1"})
        with self._open(request) as response:
            payload = json.load(response)
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ResolutionError("registry returned no anonymous pull token")
        self._tokens[cache_key] = token
        return token

    def get_manifest(self, repository: str, reference: str) -> ManifestResponse:
        quoted_reference = urllib.parse.quote(reference, safe=":")
        url = f"https://{self.registry}/v2/{repository}/manifests/{quoted_reference}"
        headers = {"Accept": ACCEPT, "User-Agent": "owasp-llm-live-validator/1"}

        def request() -> urllib.request.Request:
            return urllib.request.Request(url, headers=headers)

        try:
            response = self._open(request())
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise ResolutionError(
                    f"manifest lookup failed for {repository}:{reference}: HTTP {exc.code}"
                ) from exc
            challenge = exc.headers.get("WWW-Authenticate", "")
            token = self._token_for(challenge)
            headers["Authorization"] = f"Bearer {token}"
            try:
                response = self._open(request())
            except urllib.error.HTTPError as retry_exc:
                raise ResolutionError(
                    f"authenticated manifest lookup failed for {repository}:{reference}: "
                    f"HTTP {retry_exc.code}"
                ) from retry_exc

        with response:
            body = response.read()
            header_digest = response.headers.get("Docker-Content-Digest", "")
            content_type = response.headers.get_content_type()
        computed_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
        if header_digest and header_digest != computed_digest:
            raise ResolutionError(
                f"registry digest mismatch for {repository}:{reference}: "
                f"header={header_digest} computed={computed_digest}"
            )
        digest = header_digest or computed_digest
        if not DIGEST_RE.fullmatch(digest):
            raise ResolutionError(f"invalid registry digest for {repository}:{reference}")
        try:
            document = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ResolutionError(f"manifest is not JSON for {repository}:{reference}") from exc
        if not isinstance(document, dict):
            raise ResolutionError(f"manifest root is not an object for {repository}:{reference}")
        media_type = str(document.get("mediaType") or content_type)
        return ManifestResponse(digest, media_type, body, document)


def resolve_images(
    registry: str, namespace: str, tag: str, client: RegistryClient
) -> dict[str, Any]:
    if registry != CANONICAL_REGISTRY:
        raise ResolutionError(f"IMAGE_REGISTRY must be {CANONICAL_REGISTRY}")
    if not NAMESPACE_RE.fullmatch(namespace):
        raise ResolutionError("IMAGE_NAMESPACE is not a valid lowercase registry namespace")
    if not TAG_RE.fullmatch(tag):
        raise ResolutionError("IMAGE_TAG must be sha- followed by a 40-character lowercase commit")

    resolved: list[dict[str, Any]] = []
    for image in IMAGES:
        repository = f"{namespace}/owasp-llm-{image}"
        tag_manifest = client.get_manifest(repository, tag)
        platform_digest = tag_manifest.digest
        platform_media_type = tag_manifest.media_type
        if tag_manifest.media_type in INDEX_MEDIA_TYPES or "manifests" in tag_manifest.document:
            platform_digest = _select_linux_amd64(tag_manifest.document)
            child = client.get_manifest(repository, platform_digest)
            if child.digest != platform_digest:
                raise ResolutionError(
                    f"linux/amd64 descriptor mismatch for {repository}:{tag}"
                )
            platform_media_type = child.media_type
        resolved.append(
            {
                "name": image,
                "reference": f"{registry}/{repository}:{tag}",
                "tag_digest": tag_manifest.digest,
                "linux_amd64_digest": platform_digest,
                "tag_media_type": tag_manifest.media_type,
                "linux_amd64_media_type": platform_media_type,
            }
        )
    return {
        "schema": "owasp-llm-image-digests/v1",
        "registry": registry,
        "namespace": namespace,
        "tag": tag,
        "images": resolved,
    }


def _write_json(document: Mapping[str, Any], output: str | None) -> None:
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
        return
    destination = pathlib.Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    except BaseException:
        pathlib.Path(temporary_name).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", default=CANONICAL_REGISTRY)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    try:
        result = resolve_images(
            args.registry,
            args.namespace,
            args.tag,
            RegistryClient(args.registry, args.timeout),
        )
        _write_json(result, args.output)
    except (ResolutionError, OSError, urllib.error.URLError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
