#!/usr/bin/env bash
#
# drain-scan 0-FP probe. Runs every ported core detector over the whole real-safe corpus
# (vendored OZ / Solady / Permit2 + each vector's c-safe-impl tier) and asserts SILENCE -
# the broad-sweep precision check behind the "0 false positives" claim. See
# docs/zero-fp-probe.md. Companion to validate/all.sh; shares its env/preflight.
#
# Engine: the drain-scan analysis core (solc AST, no Slither). Only solc + python are needed.
#
# Usage:
#   validate/zero_fp_probe.sh
#   WAL_ROOT=/path/to/wallet-harness validate/zero_fp_probe.sh
#   validate/zero_fp_probe.sh --rule R2        # probe one rule
#
# Exit non-zero if any rule fires on any compiled safe file (an FP).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"
WAL_ROOT="${WAL_ROOT:-$HOME/wal}"
SOLC_VERSION="${SOLC_VERSION:-0.8.24}"

if [ ! -x "$VENV/bin/python3" ]; then
  echo "error: venv not found at $VENV (see validate/README.md)" >&2
  exit 2
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"

if ! solc-select use "$SOLC_VERSION" >/dev/null 2>&1; then
  echo "error: solc $SOLC_VERSION not installed. Run: solc-select install $SOLC_VERSION" >&2
  exit 2
fi
if [ ! -d "$WAL_ROOT" ]; then
  echo "error: WAL_ROOT not found: $WAL_ROOT" >&2
  exit 2
fi

exec python3 "$REPO_ROOT/validate/zero_fp_probe.py" --wal-root "$WAL_ROOT" "$@"
