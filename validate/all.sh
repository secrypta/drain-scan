#!/usr/bin/env bash
#
# drain-scan full benchmark. Runs EVERY rule's detector (core detectors/*.py and semgrep
# semgrep/*.yaml, dispatched by the detector's extension in the anchor rows) over its labeled
# wallet-harness anchors and prints per-rule + OVERALL precision/recall/F1 - separately for the
# DEV anchors (validate/anchors.tsv) and the independent HOLDOUT anchors
# (validate/anchors.holdout.tsv). This is the scanner benchmark and the drain-scan <-> drain-bench
# link: the dev/holdout split mirrors the drain-bench dataset manifest's `split` column.
#
# Usage:
#   validate/all.sh
#   WAL_ROOT=/path/to/wallet-harness validate/all.sh
#
# Exit code is non-zero if DEV fails (any FP/FN/compile error). HOLDOUT is reported but, while
# its corpus is still growing, does not by itself fail the run unless STRICT_HOLDOUT=1.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"
WAL_ROOT="${WAL_ROOT:-$HOME/wal}"
SOLC_VERSION="${SOLC_VERSION:-0.8.24}"
STRICT_HOLDOUT="${STRICT_HOLDOUT:-0}"

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

DEV_ANCHORS="$REPO_ROOT/validate/anchors.tsv"
HOLDOUT_ANCHORS="$REPO_ROOT/validate/anchors.holdout.tsv"

run_split() {
  # $1 = label, $2 = anchors file
  python3 "$REPO_ROOT/validate/driver.py" --wal-root "$WAL_ROOT" --anchors "$2" --label "$1"
}

# count non-comment, non-blank rows in an anchors file (grep -c prints the number itself;
# exit 1 on zero matches is swallowed so only one integer is emitted)
data_rows() { grep -cvE '^[[:space:]]*(#|$)' "$1" 2>/dev/null || true; }

echo "######################## drain-scan benchmark ########################"
echo

run_split DEV "$DEV_ANCHORS"
dev_rc=$?

echo
echo "----------------------------------------------------------------------"
echo

holdout_rc=0
if [ -f "$HOLDOUT_ANCHORS" ] && [ "$(data_rows "$HOLDOUT_ANCHORS")" -gt 0 ]; then
  run_split HOLDOUT "$HOLDOUT_ANCHORS"
  holdout_rc=$?
else
  echo "== OVERALL [HOLDOUT] ==  no anchors yet (holdout corpus not merged; see anchors.holdout.tsv)"
fi

echo
echo "######################################################################"
rc=0
[ "$dev_rc" -ne 0 ] && { echo "DEV: FAIL"; rc=1; } || echo "DEV: OK"
if [ -f "$HOLDOUT_ANCHORS" ] && [ "$(data_rows "$HOLDOUT_ANCHORS")" -gt 0 ]; then
  if [ "$holdout_rc" -ne 0 ]; then
    echo "HOLDOUT: FAIL"
    [ "$STRICT_HOLDOUT" = "1" ] && rc=1
  else
    echo "HOLDOUT: OK"
  fi
else
  echo "HOLDOUT: pending (no anchors)"
fi
exit "$rc"
