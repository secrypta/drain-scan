#!/usr/bin/env bash
#
# drain-scan - Semgrep validation loop.
#
# For each Semgrep rule, assert it FIRES on its vulnerable PoC anchor and stays SILENT on
# its safe anchor(s) (0 false positives). Anchors are wallet-harness fixtures, read-only.
# Prints a per-anchor PASS/FAIL and an overall precision/recall-style summary.
#
# Usage:  WAL=~/wal validate/run_semgrep.sh       (WAL defaults to ~/wal)
# Requires: semgrep on PATH (see README; e.g. a .venv with `pip install semgrep`).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAL="${WAL:-$HOME/wal}"
SG="$REPO_ROOT/semgrep"
cd "$REPO_ROOT"

if ! command -v semgrep >/dev/null 2>&1; then
  echo "error: semgrep not found on PATH. Activate the venv (. .venv/bin/activate) first." >&2
  exit 1
fi
if [ ! -d "$WAL/src" ]; then
  echo "error: wal corpus not found at WAL=$WAL (set WAL=/path/to/wallet-harness)." >&2
  exit 1
fi

# Each row: rule_file | expect(fire|silent) | anchor_path (relative to $WAL)
# A rule must FIRE on every 'fire' row and stay SILENT on every 'silent' row.
CASES=(
  "R2-set-approval-for-all-arbitrary-operator.yaml|fire|src/VulnerableWalletNFT.sol"
  "R2-set-approval-for-all-arbitrary-operator.yaml|silent|src/SafeWalletNFT.sol"
  "R2-set-approval-for-all-arbitrary-operator.yaml|silent|fixtures/set-approval-for-all/c-safe-impl/SafeOperatorFlow.sol"
  "R6-ecrecover-raw-digest.yaml|fire|src/BlindSignVector.sol"
  "R6-ecrecover-raw-digest.yaml|silent|fixtures/blind-eth-sign/c-safe-impl/ClearSigningWallet.sol"
  "R10-upgrade-without-timelock.yaml|fire|src/VulnerableUpgradeWallet.sol"
  "R10-upgrade-without-timelock.yaml|silent|src/SafeUpgradeWallet.sol"
  "R10-upgrade-without-timelock.yaml|silent|fixtures/upgrade-governance/c-safe-impl/oz-timelock-safe/OZTimelockUUPSWallet.sol"
)

count() { # rule target -> number of findings
  semgrep --jobs 1 --quiet --json --config "$1" "$2" 2>/dev/null \
    | python3 -I -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))"
}

pass=0; fail=0
tp=0; fn=0; tn=0; fp=0
echo "== drain-scan semgrep validation (WAL=$WAL) =="
for row in "${CASES[@]}"; do
  IFS='|' read -r rule expect rel <<<"$row"
  tgt="$WAL/$rel"
  if [ ! -f "$tgt" ]; then echo "MISS  $rule  (anchor not found: $rel)"; fail=$((fail+1)); continue; fi
  n="$(count "$SG/$rule" "$tgt")"
  if [ "$expect" = "fire" ]; then
    if [ "$n" -ge 1 ]; then echo "PASS  fire    n=$n  $rule  <- $rel"; pass=$((pass+1)); tp=$((tp+1));
    else echo "FAIL  fire    n=0  $rule  <- $rel (expected a finding)"; fail=$((fail+1)); fn=$((fn+1)); fi
  else
    if [ "$n" -eq 0 ]; then echo "PASS  silent  n=0  $rule  <- $rel"; pass=$((pass+1)); tn=$((tn+1));
    else echo "FAIL  silent  n=$n  $rule  <- $rel (false positive)"; fail=$((fail+1)); fp=$((fp+1)); fi
  fi
done

echo
echo "== summary =="
echo "  cases: $((pass+fail))  PASS=$pass  FAIL=$fail"
echo "  TP=$tp FN=$fn  TN=$tn FP=$fp"
prec="n/a"; rec="n/a"
[ $((tp+fp)) -gt 0 ] && prec="$(python3 -I -c "print(f'{$tp/($tp+$fp):.3f}')")"
[ $((tp+fn)) -gt 0 ] && rec="$(python3 -I -c "print(f'{$tp/($tp+$fn):.3f}')")"
echo "  precision=$prec  recall=$rec"
[ "$fail" -eq 0 ] && { echo "== VALIDATION: OK =="; exit 0; } || { echo "== VALIDATION: FAIL =="; exit 1; }
