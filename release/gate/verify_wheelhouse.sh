#!/usr/bin/env bash
# Verify the offline wheelhouse against its pinned SHA-256 lock.
# The gate calls this logic itself; this wrapper exists for CI/Make use and
# for operators to re-check the supply chain without running a build.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEELHOUSE="$HERE/wheelhouse"

if [ ! -f "$WHEELHOUSE/SHA256SUMS" ]; then
  echo "FATAL: $WHEELHOUSE/SHA256SUMS missing; run bootstrap_wheelhouse.sh first" >&2
  exit 1
fi

# Fail on any wheel that is not covered by the lock as well as hash drift.
(
  cd "$WHEELHOUSE"
  sha256sum -c SHA256SUMS
  locked="$(awk '{print $2}' SHA256SUMS | sort)"
  present="$(find . -maxdepth 1 -name '*.whl' -printf '%f\n' | sort)"
  if [ "$locked" != "$present" ]; then
    echo "FATAL: wheelhouse contents do not match the lock:" >&2
    diff -u <(echo "$locked") <(echo "$present") >&2 || true
    exit 1
  fi
)
echo "wheelhouse lock verified: $WHEELHOUSE"
