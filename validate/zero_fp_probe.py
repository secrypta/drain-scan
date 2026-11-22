#!/usr/bin/env python3
"""drain-scan 0-FP probe runner (core engine; no Slither).

Precision discipline, broad sweep. Where validate/driver.py checks a few hand-picked safe
*anchors* per rule, this probe runs EVERY ported detector over a whole corpus of real,
independent, known-safe code (vendored OpenZeppelin / Solady / Uniswap Permit2, plus the
`c-safe-impl` real-safe tier of every vector) and asserts SILENCE. Any finding is a
false-positive candidate to triage. See docs/zero-fp-probe.md for the plan and the triage
workflow (FPs go to the detector owners A/B/D; never path-suppressed).

Engine-agnostic by construction: it reuses the same core API the scanner/driver use
(core.compile + core.ast.Unit + core.detector.Detector) and driver.load_core_detector, so it
tracks the solc-AST core with no Slither dependency. Detectors are AUTO-DISCOVERED
(detectors/r*.py), so as A/B/D port each rule the probe covers it with no edit here.

Usage:
    validate/zero_fp_probe.py [--wal-root DIR] [--rule R2] [--list]
Exit non-zero if any rule fires on any compiled safe file (an FP), else 0. Files that do not
compile under the pinned solc are reported as 'uncompilable' (a coverage note, not an FP).
"""
import argparse
import glob
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "validate"))

from core import compile as core_compile  # noqa: E402
from core.ast import Unit  # noqa: E402
from driver import load_core_detector  # noqa: E402  (reuse the loader, do not duplicate it)

# Known-safe corpus, relative to --wal-root (the read-only wallet-harness checkout). Real,
# audited, independent code the detectors were NEVER tuned against -> genuine precision test.
SAFE_GLOBS = (
    "fixtures/vendor/oz/**/*.sol",
    "fixtures/vendor/solady/**/*.sol",
    "fixtures/vendor/solady-accounts/**/*.sol",
    "fixtures/vendor/permit2/**/*.sol",
    "fixtures/*/c-safe-impl/**/*.sol",
)


def discover_core_detectors():
    """Every ported core detector module (detectors/r*.py). Returns [(rule_id, module_rel)]."""
    out = []
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "detectors", "r*.py"))):
        module_rel = os.path.relpath(path, REPO_ROOT)
        try:
            det = load_core_detector(module_rel)
        except Exception as exc:  # a half-written detector must not silently vanish
            print(f"warning: could not load {module_rel}: {exc}", file=sys.stderr)
            continue
        out.append((det.rule_id or module_rel, module_rel, det))
    return out


def discover_corpus(wal_root):
    """All safe .sol files under the corpus globs (deduped, sorted)."""
    seen = set()
    files = []
    for pat in SAFE_GLOBS:
        for p in glob.glob(os.path.join(wal_root, pat), recursive=True):
            rp = os.path.relpath(p, wal_root)
            if p not in seen and p.endswith(".sol"):
                seen.add(p)
                files.append((rp, p))
    return sorted(files)


def main():
    ap = argparse.ArgumentParser(description="drain-scan 0-FP probe (core engine)")
    ap.add_argument("--wal-root", default=os.path.expanduser("~/wal"))
    ap.add_argument("--rule", default=None, help="probe only this rule id (e.g. R2)")
    ap.add_argument("--list", action="store_true", help="list detectors + corpus and exit")
    args = ap.parse_args()

    wal_root = os.path.abspath(os.path.expanduser(args.wal_root))
    if not os.path.isdir(wal_root):
        print(f"error: --wal-root not a directory: {wal_root}", file=sys.stderr)
        return 2

    detectors = discover_core_detectors()
    if args.rule:
        detectors = [d for d in detectors if d[0] == args.rule]
    corpus = discover_corpus(wal_root)

    print(f"== drain-scan 0-FP probe ==  wal-root={wal_root}")
    print(f"detectors (ported core): {', '.join(r for r, _, _ in detectors) or '(none)'}")
    print(f"corpus: {len(corpus)} safe .sol files\n")
    if args.list:
        for rp, _ in corpus:
            print(f"  corpus  {rp}")
        return 0
    if not detectors:
        print("no core detectors ported yet - nothing to probe (not a failure).")
        return 0

    # Compile each file once, run every detector over it. All corpus files are SAFE, so any
    # finding is a false-positive candidate.
    per_rule_fp = {r: 0 for r, _, _ in detectors}
    per_rule_files = {r: 0 for r, _, _ in detectors}
    fp_rows = []          # (rule, location, message)
    uncompilable = []     # (rel_path, err)
    compiled = 0

    for rp, abs_path in corpus:
        try:
            data = core_compile.compile_source(abs_path, allow_paths=wal_root)
            unit = Unit.from_compile(data)
        except core_compile.CompileError as exc:
            uncompilable.append((rp, str(exc).splitlines()[0][:140]))
            continue
        except Exception as exc:  # analysis failure is a hard note, never silent
            uncompilable.append((rp, f"{type(exc).__name__}: {exc}"))
            continue
        compiled += 1
        for rule_id, _module, det in detectors:
            per_rule_files[rule_id] += 1
            try:
                findings = det.detect(unit)
            except Exception as exc:
                fp_rows.append((rule_id, rp, f"DETECTOR ERROR: {type(exc).__name__}: {exc}"))
                per_rule_fp[rule_id] += 1
                continue
            for f in findings:
                per_rule_fp[rule_id] += 1
                fp_rows.append((rule_id, f.location(), f.message))

    print(f"compiled {compiled}/{len(corpus)} files "
          f"({len(uncompilable)} uncompilable under the pinned solc)\n")

    print("== per-rule false positives ==")
    any_fp = False
    for rule_id, _m, _d in detectors:
        k = per_rule_fp[rule_id]
        status = "PASS" if k == 0 else "FP-CANDIDATES"
        if k:
            any_fp = True
        print(f"  {rule_id:<5} files={per_rule_files[rule_id]:<4} findings={k:<3} [{status}]")

    if fp_rows:
        print("\n== FP candidates (triage to detector owner; do NOT path-suppress) ==")
        for rule_id, loc, msg in fp_rows:
            print(f"  [{rule_id}] {loc}  {msg}")

    if uncompilable:
        print("\n== uncompilable (not probed; coverage note, not an FP) ==")
        for rp, err in uncompilable:
            print(f"  {rp}  -- {err}")

    print()
    if any_fp:
        print("== PROBE: FAIL (false positives on real safe code) ==")
        return 1
    print("== PROBE: OK - 0 false positives on the real safe corpus ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
