#!/bin/bash
# LLM09의 현재 PyPI 404 후보 하나를 완전 격리된 로컬 mirror에 등록하고,
# 별도 victim 컨테이너에서 설치 뒤 무해한 .pth signal만 확인한다.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL_GUARD="$SCRIPT_DIR/../lib/require_loopback_url.py"

: "${SLOPSQUAT_PACKAGE:?SLOPSQUAT_PACKAGE에 현재 실측한 PyPI NOT_FOUND 후보가 필요합니다}"
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)}"
: "${PYTHON_IMAGE:=docker.io/library/python:3.12-slim}"

if [[ ! "$SLOPSQUAT_PACKAGE" =~ ^[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
  echo "ERROR: package name must be a normalized lowercase PyPI name" >&2
  exit 2
fi

command -v podman >/dev/null 2>&1 || {
  echo "INFRA: podman is required" >&2
  exit 3
}

LAB_DIR="$RESULTS_DIR/isolated-slopsquat"
MIRROR_DIR="$LAB_DIR/mirror"
EVIDENCE_DIR="$LAB_DIR/evidence"
RAW_DIR="$LAB_DIR/raw"
NETWORK="llm09-internal-$$"
MIRROR_CONTAINER="llm09-mirror-$$"
mkdir -p "$MIRROR_DIR" "$EVIDENCE_DIR" "$RAW_DIR"

if ! PYPI_STATUS="$(curl -sS -L -o /dev/null --max-time 10 \
  -w '%{http_code}' "https://pypi.org/simple/$SLOPSQUAT_PACKAGE/")"; then
  echo "INFRA: public PyPI baseline check failed" >&2
  exit 3
fi
printf 'package=%s\nhttp_status=%s\nclassification=%s\n' \
  "$SLOPSQUAT_PACKAGE" "$PYPI_STATUS" \
  "$([ "$PYPI_STATUS" = 404 ] || [ "$PYPI_STATUS" = 410 ] && echo NOT_FOUND || echo EXISTS_OR_UNKNOWN)" \
  >"$RAW_DIR/pypi-baseline.txt"
case "$PYPI_STATUS" in
  404|410) ;;
  *)
    echo "FAIL: candidate is not a current PyPI NOT_FOUND name (HTTP $PYPI_STATUS)" >&2
    exit 1
    ;;
esac

cleanup() {
  podman rm -f "$MIRROR_CONTAINER" >/dev/null 2>&1 || true
  podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Pure-Python wheel을 직접 만든다. payload는 외부 통신·명령 실행 없이 victim에
# 마운트한 evidence 파일 한 개만 쓴다. RECORD hash와 mirror 링크 hash도 고정한다.
python3 - "$SLOPSQUAT_PACKAGE" "$MIRROR_DIR" <<'PY'
from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import pathlib
import sys
import zipfile

package = sys.argv[1]
mirror = pathlib.Path(sys.argv[2])
normalized = package.replace("-", "_").replace(".", "_")
canonical = package.replace("_", "-").replace(".", "-")
version = "0.0.1"
wheel_name = f"{normalized}-{version}-py3-none-any.whl"
dist_info = f"{normalized}-{version}.dist-info"
packages_dir = mirror / "packages"
simple_dir = mirror / "simple" / canonical
packages_dir.mkdir(parents=True, exist_ok=True)
simple_dir.mkdir(parents=True, exist_ok=True)
wheel_path = packages_dir / wheel_name

files = {
    f"{normalized}_training.pth": (
        "import pathlib; pathlib.Path('/evidence/install-signal.txt').write_text("
        f"'package={package}\\ncode=SAFE_SLOPSQUAT_SIGNAL\\n', encoding='utf-8')"
    ).encode(),
    f"{dist_info}/METADATA": (
        "Metadata-Version: 2.1\n"
        f"Name: {package}\nVersion: {version}\n"
        "Summary: Isolated OWASP LLM09 training fixture\n"
    ).encode(),
    f"{dist_info}/WHEEL": (
        "Wheel-Version: 1.0\nGenerator: owasp-llm-lab\n"
        "Root-Is-Purelib: true\nTag: py3-none-any\n"
    ).encode(),
}

record_rows = []
for name, content in files.items():
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    record_rows.append((name, f"sha256={digest}", str(len(content))))
record_name = f"{dist_info}/RECORD"
record_rows.append((record_name, "", ""))
record_buffer = io.StringIO(newline="")
csv.writer(record_buffer).writerows(record_rows)
files[record_name] = record_buffer.getvalue().encode()

with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
    for name, content in files.items():
        archive.writestr(name, content)

wheel_sha = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
(simple_dir / "index.html").write_text(
    f'<a href="../../packages/{html.escape(wheel_name)}#sha256={wheel_sha}">'
    f'{html.escape(wheel_name)}</a>\n',
    encoding="utf-8",
)
(mirror / "simple" / "index.html").write_text(
    f'<a href="{html.escape(canonical)}/">{html.escape(package)}</a>\n',
    encoding="utf-8",
)
(mirror / "fixture.json").write_text(
    '{"package":"%s","version":"%s","wheel":"%s","sha256":"%s"}\n'
    % (package, version, wheel_name, wheel_sha),
    encoding="utf-8",
)
PY

podman network create --internal "$NETWORK" >"$RAW_DIR/network-create.txt"
podman run -d --name "$MIRROR_CONTAINER" \
  --network "$NETWORK" \
  -v "$MIRROR_DIR:/srv:ro" -w /srv \
  "$PYTHON_IMAGE" python -m http.server 8003 \
  >"$RAW_DIR/mirror-container-id.txt"

mirror_ready=false
for _ in $(seq 1 20); do
  if podman run --rm --network "$NETWORK" "$PYTHON_IMAGE" \
    python -c 'import urllib.request; urllib.request.urlopen("http://'"$MIRROR_CONTAINER"':8003/simple/", timeout=3).read()' \
    >"$RAW_DIR/mirror-reachability.txt" 2>&1; then
    mirror_ready=true
    break
  fi
  sleep 1
done
[ "$mirror_ready" = true ] || {
  echo "INFRA: isolated mirror was not reachable" >&2
  exit 3
}

# --internal network에서 public PyPI가 열리면 격리 계약 위반이다.
if podman run --rm --network "$NETWORK" "$PYTHON_IMAGE" \
  python -c 'import urllib.request; urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=3).read(1)' \
  >"$RAW_DIR/egress-probe.txt" 2>&1; then
  echo "FAIL: victim network unexpectedly reached public PyPI" >&2
  exit 1
fi

podman run --rm --network "$NETWORK" \
  -v "$EVIDENCE_DIR:/evidence" \
  "$PYTHON_IMAGE" sh -ec '
    python -m pip install --disable-pip-version-check --no-cache-dir --no-deps \
      --index-url "http://'"$MIRROR_CONTAINER"':8003/simple/" \
      --trusted-host "'"$MIRROR_CONTAINER"'" "'"$SLOPSQUAT_PACKAGE"'"
    python -c "pass"
    test -s /evidence/install-signal.txt
  ' >"$RAW_DIR/victim-install.txt" 2>&1

grep -Fx "package=$SLOPSQUAT_PACKAGE" "$EVIDENCE_DIR/install-signal.txt" >/dev/null
grep -Fx "code=SAFE_SLOPSQUAT_SIGNAL" "$EVIDENCE_DIR/install-signal.txt" >/dev/null

python3 - "$LAB_DIR" "$SLOPSQUAT_PACKAGE" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
package = sys.argv[2]
files = {}
for path in sorted(root.rglob("*")):
    if path.is_file():
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
(root / "result.json").write_text(
    json.dumps(
        {
            "test_id": "LLM09-isolated-slopsquat",
            "package": package,
            "mirror_reachable": True,
            "public_egress_blocked": True,
            "victim_install_signal": "SAFE_SLOPSQUAT_SIGNAL",
            "file_sha256": files,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

echo "PASS: isolated mirror + blocked egress + victim install signal"
echo "evidence=$LAB_DIR/result.json"
