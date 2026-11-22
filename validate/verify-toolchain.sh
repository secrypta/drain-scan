#!/usr/bin/env bash
#
# Toolchain pre-flight verifier (CLAUDE.md §Toolchain). Run this AFTER any venv rebuild and
# BEFORE validate/all.sh / zero_fp_probe.sh.
#
# It guards the VM against the fork-bomb that froze it (VM-freeze #4, 2026-11-20): a corrupt
# solc artifact that is really a `#!python` solc-select entry-point (or a symlink to one)
# re-execs itself without bound when run. For every installed solc artifact we assert:
#   (a) it is a real ELF binary  - NOT a #!script / wrapper symlink (hard fail: the fork-bomb);
#   (b) its sha256 matches a known-good value - the shared manifest if present, else the
#       built-in official hash for the versions we can authoritatively pin.
#
# Non-ELF or sha mismatch -> exit 1 (do NOT run the gate; stop and report it). ELF-check is the
# hard, always-on guard; sha-check degrades to a warning only when no trusted source is
# available for a given version (the versioned manifest is the toolchain-provisioning deliverable).
#
# Usage: validate/verify-toolchain.sh            # verify the active venv's solc-select artifacts
#        SOLC_ARTIFACTS=/path validate/verify-toolchain.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${SOLC_MANIFEST:-$REPO_ROOT/validate/solc-manifest.sha256}"

# Official solc sha256 we have authoritatively verified against binaries.soliditylang.org.
# 0.8.24 is the version that caused the incident; pin it so the regression can never return.
declare -A OFFICIAL_SHA=(
  ["0.8.24"]="fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f"
)

# Locate the solc-select artifacts dir (mirror core/compile.py: venv first, then ~).
if [ -n "${SOLC_ARTIFACTS:-}" ]; then
  ART="$SOLC_ARTIFACTS"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -d "$VIRTUAL_ENV/.solc-select/artifacts" ]; then
  ART="$VIRTUAL_ENV/.solc-select/artifacts"
elif [ -d "$REPO_ROOT/.venv/.solc-select/artifacts" ]; then
  ART="$REPO_ROOT/.venv/.solc-select/artifacts"
else
  ART="$HOME/.solc-select/artifacts"
fi

[ -d "$ART" ] || { echo "verify-toolchain: artifacts dir not found: $ART" >&2; exit 2; }
echo "verify-toolchain: artifacts = $ART"
[ -f "$MANIFEST" ] && echo "verify-toolchain: manifest = $MANIFEST" || echo "verify-toolchain: no manifest ($MANIFEST) - sha checked against built-in official pins only"

rc=0
shopt -s nullglob
for dir in "$ART"/solc-*; do
  ver="$(basename "$dir")"; ver="${ver#solc-}"
  bin="$dir/solc-$ver"
  [ -e "$bin" ] || { echo "MISSING  $ver  ($bin)"; rc=1; continue; }

  # (a) ELF magic of the RESOLVED target - rejects #! wrappers / symlinks to solc-select.
  real="$(readlink -f "$bin" 2>/dev/null || echo "$bin")"
  magic="$(head -c4 "$real" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  if [ "$magic" != "7f454c46" ]; then
    echo "NOT-ELF  $ver  -> $real (magic 0x$magic) = WRAPPER/corrupt -> FORK-BOMB RISK"
    rc=1; continue
  fi

  # (b) sha256 against manifest, else built-in official pin, else ELF-only note.
  sha="$(sha256sum "$real" | awk '{print $1}')"
  want=""
  if [ -f "$MANIFEST" ]; then
    want="$(awk -v v="$ver" '$1==v{print $2}' "$MANIFEST")"
  fi
  [ -z "$want" ] && want="${OFFICIAL_SHA[$ver]:-}"

  if [ -n "$want" ]; then
    if [ "$sha" = "$want" ]; then
      echo "OK       $ver  ELF + sha256 verified"
    else
      echo "SHA-MISMATCH $ver  got $sha want $want"
      rc=1
    fi
  else
    echo "ELF-only $ver  (real ELF; no trusted sha for this version - add it to the manifest)  sha=$sha"
  fi
done

echo
if [ "$rc" -eq 0 ]; then
  echo "verify-toolchain: PASS - all solc artifacts are real ELF, no fork-bomb risk."
else
  echo "verify-toolchain: FAIL - do NOT run all.sh/zero_fp; stop here." >&2
fi
exit "$rc"
