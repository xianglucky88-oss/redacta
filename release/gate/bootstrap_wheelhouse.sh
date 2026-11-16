#!/usr/bin/env bash
# One-time network bootstrap for the OFFLINE release gate.
#
# Everything needed afterwards (pip, setuptools, wheel) is materialised under
# release/gate/wheelhouse. The gate itself always runs with PIP_NO_INDEX=1 and
# --no-index, so a populated wheelhouse means the build/install path never
# touches the network again.
#
# Usage: bash release/gate/bootstrap_wheelhouse.sh [index-url]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEELHOUSE="$HERE/wheelhouse"
INDEX="${1:-https://pypi.org}"
PYTHON="${PYTHON:-python3}"
PY_VER="$("$PYTHON" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"

# Pure-python wheels: no ABI/platform matrix, pinned for reproducibility.
# setuptools is pinned at 70.x because 71+ stopped vendoring jaraco/etc.,
# which would force transitive dependency wheels into the offline lock.
REQUIREMENTS=(
  "pip==24.3.1"
  "setuptools==70.3.0"
  "wheel==0.45.1"
)
# Expected SHA-256 of every wheel; the offline gate re-verifies these before
# bootstrapping a build environment (see verify_wheelhouse.sh).
declare -A EXPECTED_SHA=(
  ["pip-24.3.1-py3-none-any.whl"]="3790624780082365f47549d032f3770eeb2b1e8bd1f7b2e02dace1afa361b4ed"
  ["setuptools-70.3.0-py3-none-any.whl"]="fe384da74336c398e0d956d1cae0669bc02eed936cdb1d49b57de1990dc11ffc"
  ["wheel-0.45.1-py3-none-any.whl"]="708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248"
)

mkdir -p "$WHEELHOUSE"

# Fast path: an existing, lock-matching wheelhouse is reused as-is, so normal
# gate runs never touch the network.
if [ -f "$WHEELHOUSE/SHA256SUMS" ] && ( cd "$WHEELHOUSE" && sha256sum -c --quiet SHA256SUMS ) 2>/dev/null; then
  locked_count="$(grep -c '  ' "$WHEELHOUSE/SHA256SUMS")"
  present_count="$(find "$WHEELHOUSE" -maxdepth 1 -name '*.whl' | wc -l)"
  if [ "$locked_count" -eq "$present_count" ] && [ "$locked_count" -eq "${#REQUIREMENTS[@]}" ]; then
    echo "wheelhouse already complete and hash-locked at $WHEELHOUSE; skipping download"
    exit 0
  fi
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Download with the stdlib only (no pre-existing pip assumed).
# $INDEX may point at any PyPI-compatible host; /pypi/<name>/<version>/json
# is the JSON release metadata endpoint.
"$PYTHON" - "$INDEX" "$tmp" "${REQUIREMENTS[@]}" <<'PY'
import json, sys, urllib.request
from urllib.parse import quote

host, dest, *requirements = sys.argv[1:]
for spec in requirements:
    name, _, version = spec.partition("==")
    url = f"{host.rstrip('/')}/pypi/{quote(name)}/{quote(version)}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        data = json.load(response)
    candidates = [u for u in data["urls"] if u["packagetype"] == "bdist_wheel"]
    # Prefer universal pure-python wheels; fall back to cp3-none-any wheels.
    candidates.sort(key=lambda u: (not u["filename"].endswith(
        ("py3-none-any.whl", "py2.py3-none-any.whl")), u["filename"]))
    if not candidates:
        raise SystemExit(f"no wheel published for {spec}")
    match = candidates[0]
    target = f"{dest}/{match['filename']}"
    urllib.request.urlretrieve(match["url"], target)
    print(f"downloaded {match['filename']} sha256={match['digests']['sha256']}")
PY

# Verify every download against the pinned SHA-256 before trusting it.
for wheel in "$tmp"/*.whl; do
  name="$(basename "$wheel")"
  actual="$(sha256sum "$wheel" | cut -d' ' -f1)"
  if [ "${EXPECTED_SHA[$name]:-}" != "$actual" ]; then
    echo "FATAL: hash mismatch for $name (got $actual)" >&2
    exit 1
  fi
done

# Prove the wheelhouse is self-sufficient: build a venv without pip, then
# install the wheels using --no-index only.
# SETUPTOOLS_USE_DISTUTILS=stdlib avoids the _distutils_hack assertion on
# Debian images where python3-distutils shadows the vendored copy in a
# --without-pip venv.
export SETUPTOOLS_USE_DISTUTILS=stdlib
"$PYTHON" -m venv --without-pip "$tmp/probe-venv"
pip_wheel1="$(find "$tmp" -maxdepth 1 -name 'pip-*.whl' -print -quit)"
PYTHONPATH="$pip_wheel1" "$tmp/probe-venv/bin/python" -m pip install \
  --no-index --find-links "$tmp" pip setuptools wheel >/dev/null
"$tmp/probe-venv/bin/python" - <<'PY'
import pip, setuptools, wheel
print("probe venv:", pip.__version__, setuptools.__version__, wheel.__version__)
PY

mv "$tmp"/*.whl "$WHEELHOUSE"/ 2>/dev/null || true
# Re-prove against the final wheelhouse location.
"$PYTHON" -m venv --without-pip "$tmp/probe-venv2"
pip_wheel2="$(find "$WHEELHOUSE" -maxdepth 1 -name 'pip-*.whl' -print -quit)"
PYTHONPATH="$pip_wheel2" "$tmp/probe-venv2/bin/python" -m pip install \
  --no-index --find-links "$WHEELHOUSE" pip setuptools wheel >/dev/null
"$tmp/probe-venv2/bin/python" -m pip --version

echo
echo "wheelhouse ready at $WHEELHOUSE (python $PY_VER)"
# Materialise the hash lock consumed by verify_wheelhouse.sh.
: > "$WHEELHOUSE/SHA256SUMS"
for name in "${!EXPECTED_SHA[@]}"; do
  echo "${EXPECTED_SHA[$name]}  $name" >> "$WHEELHOUSE/SHA256SUMS"
done
( cd "$WHEELHOUSE" && sha256sum -c SHA256SUMS )
ls -1 "$WHEELHOUSE"
