#!/usr/bin/env bash
#
# drain-scan validation loop. Runs each rule's detector - our own analysis over the solc AST,
# no Slither - over its labeled wallet-harness fixtures and asserts the rule fires on vuln
# anchors and stays silent on safe anchors (0 false positives), printing per-rule + overall
# precision/recall.
#
# Usage:
#   validate/run.sh                 # validate every rule in anchors.tsv
#   validate/run.sh R1              # validate only rule R1
#   WAL_ROOT=/path/to/wal validate/run.sh   # point at a different wallet-harness checkout
#
# Requires the project venv (validate/../.venv) with solc-select; the analysis core runs over
# the solc AST (no Slither / crytic-compile - deliberately, this is MIT). See README. Our
# fixtures are first-party, so no Docker is needed (Docker is only for 3rd-party code). The
# fixtures compile at solc 0.8.24 (Permit2 at 0.8.17, picked per-pragma).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"
WAL_ROOT="${WAL_ROOT:-$HOME/wal}"
SOLC_VERSION="${SOLC_VERSION:-0.8.24}"

if [ ! -x "$VENV/bin/python3" ]; then
  echo "error: venv not found at $VENV. Create it:" >&2
  echo "  python3 -m venv $VENV && . $VENV/bin/activate && pip install -r requirements.txt" >&2
  exit 2
fi

# shellcheck disable=SC1091
. "$VENV/bin/activate"

# Pin the solc the fixtures compile with (installed via solc-select).
if ! solc-select use "$SOLC_VERSION" >/dev/null 2>&1; then
  echo "error: solc $SOLC_VERSION not installed. Run: solc-select install $SOLC_VERSION" >&2
  exit 2
fi

if [ ! -d "$WAL_ROOT" ]; then
  echo "error: WAL_ROOT not found: $WAL_ROOT (set WAL_ROOT=/path/to/wallet-harness)" >&2
  exit 2
fi

RULE_ARG=()
if [ "${1:-}" != "" ]; then
  RULE_ARG=(--rule "$1")
fi

exec python3 "$REPO_ROOT/validate/driver.py" --wal-root "$WAL_ROOT" "${RULE_ARG[@]}"
