#!/usr/bin/env python3
"""drain-scan validation driver.

The methodology loop: for each rule, run its detector over the labeled wallet-harness
fixtures that anchor it, and assert the rule FIRES on every vulnerable anchor and stays
SILENT on every safe anchor (0 false positives). Prints a per-rule and overall confusion
matrix + precision/recall, and exits non-zero on any FP/FN or compile error. This is the
"static rule <-> executable PoC <-> labeled vuln/safe benchmark" loop.

Anchors are declared in validate/anchors.tsv (tab-separated):
    rule <TAB> detector_module <TAB> label(vuln|safe) <TAB> path <TAB> [contract] <TAB> note
`path` is relative to --wal-root (the read-only wallet-harness checkout; default ~/wal).
`detector_module` is relative to the drain-scan repo root.

Two engines, dispatched by the detector_module extension:
  *.py           -> a drain-scan CORE detector (core.detector.Detector; solc AST, no Slither)
  *.yaml / *.yml -> a Semgrep rule (run as a subprocess; syntactic, no compile)

Migration note: the analysis core replaced Slither. A *.py anchor whose module file does not
exist yet (a rule not yet ported to the core) is reported as SKIP (pending migration) and does
NOT count toward pass/fail - all.sh then covers the ported rules (R1) plus the Semgrep rules
until the remaining clusters are rewritten on the core.
"""
import argparse
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core import compile as core_compile  # noqa: E402
from core.ast import Unit  # noqa: E402
from core.detector import Detector  # noqa: E402

_DETECTOR_CACHE = {}


def load_core_detector(module_rel):
    """Load and cache the core Detector subclass defined in a detector module."""
    if module_rel in _DETECTOR_CACHE:
        return _DETECTOR_CACHE[module_rel]
    module_path = os.path.join(REPO_ROOT, module_rel)
    if not os.path.isfile(module_path):
        raise FileNotFoundError(f"detector module not found: {module_rel}")
    spec = importlib.util.spec_from_file_location(
        "drain_scan_det_" + os.path.basename(module_path).replace(".", "_"), module_path
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    dets = [
        obj
        for _, obj in inspect.getmembers(mod, inspect.isclass)
        if issubclass(obj, Detector) and obj is not Detector and obj.__module__ == mod.__name__
    ]
    if not dets:
        raise ValueError(f"no core Detector subclass in {module_rel}")
    inst = dets[0]()
    _DETECTOR_CACHE[module_rel] = inst
    return inst


def run_core(sol_path, detector, wal_root, contract=None):
    """Compile one .sol with solc and run a core detector. Returns (findings_count, err).
    When `contract` is given, only findings in that contract are counted (a file may hold a
    vuln + a safe contract)."""
    try:
        data = core_compile.compile_source(sol_path, allow_paths=wal_root)
        unit = Unit.from_compile(data)
        findings = detector.detect(unit)
    except core_compile.CompileError as exc:
        return None, str(exc)
    except Exception as exc:  # analysis failure is a hard error, never "silent"
        return None, f"{type(exc).__name__}: {exc}"
    if contract:
        findings = [f for f in findings if f.contract == contract]
    return len(findings), None


def _contract_line_span(sol_path, contract):
    """1-indexed inclusive (start, end) line range of a contract/library/interface, by a
    light brace scan (semgrep is syntactic and reports line numbers, not AST contracts)."""
    try:
        with open(sol_path) as fh:
            lines = fh.readlines()
    except OSError:
        return None
    pat = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+" + re.escape(contract) + r"\b")
    start = next((i for i, l in enumerate(lines) if pat.search(l)), None)
    if start is None:
        return None
    depth = 0
    started = False
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth <= 0:
            return (start + 1, j + 1)
    return (start + 1, len(lines))


def run_semgrep(yaml_path, sol_path, contract=None):
    """Run a semgrep rule over one .sol. Returns (match_count, error_or_None). semgrep is
    syntactic (no compile), so imports don't matter. Per-contract filtering is by line span."""
    try:
        proc = subprocess.run(
            # --jobs 1: scanning ONE .sol file; semgrep otherwise defaults to one worker
            # per CPU core and grabs all of them natively (outside Docker), so N parallel
            # branches running validate/all.sh oversubscribe every core and freeze the VM/IDE.
            ["semgrep", "scan", "--jobs", "1", "--quiet", "--config", yaml_path, "--json", sol_path],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError:
        return None, "semgrep not installed (pip install semgrep)"
    except subprocess.TimeoutExpired:
        return None, "semgrep timeout"
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None, f"semgrep error rc={proc.returncode}: {(proc.stderr or '').strip()[:200]}"
    matches = data.get("results", [])
    if contract:
        span = _contract_line_span(sol_path, contract)
        if span:
            lo, hi = span
            matches = [m for m in matches if lo <= m.get("start", {}).get("line", -1) <= hi]
    return len(matches), None


def parse_anchors(path, only_rule):
    rows = []
    with open(path) as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                raise ValueError(f"malformed anchor row (need >=4 tab fields): {line!r}")
            rule, module, label, rel_path = parts[0], parts[1], parts[2], parts[3]
            # 5 fields: ...<path><note>. 6+ fields: ...<path><contract><note>, where an
            # empty/"-" contract means "whole file" (used when a file holds one contract).
            contract = None
            note = ""
            if len(parts) == 5:
                note = parts[4]
            elif len(parts) >= 6:
                c = parts[4].strip()
                contract = None if c in ("", "-") else c
                note = parts[5]
            if label not in ("vuln", "safe"):
                raise ValueError(f"bad label {label!r} in row: {line!r}")
            if only_rule and rule != only_rule:
                continue
            rows.append((rule, module, label, rel_path, contract, note))
    return rows


def main():
    ap = argparse.ArgumentParser(description="drain-scan rule<->fixture validation loop")
    ap.add_argument("--anchors", default=os.path.join(REPO_ROOT, "validate", "anchors.tsv"))
    ap.add_argument("--wal-root", default=os.path.expanduser("~/wal"))
    ap.add_argument("--rule", default=None, help="validate only this rule id (e.g. R1)")
    ap.add_argument("--label", default=None, help="tag for the report header (e.g. DEV, HOLDOUT)")
    args = ap.parse_args()

    wal_root = os.path.abspath(os.path.expanduser(args.wal_root))
    if not os.path.isdir(wal_root):
        print(f"error: --wal-root not a directory: {wal_root}", file=sys.stderr)
        return 2

    rows = parse_anchors(args.anchors, args.rule)
    tag = f" [{args.label}]" if args.label else ""
    if not rows:
        # Not an error: a split (e.g. HOLDOUT) may simply have no anchors yet.
        print(f"== drain-scan validation{tag} ==  (no anchors in {os.path.basename(args.anchors)})")
        return 0

    # tallies
    per_rule = {}  # rule -> dict(TP,FP,FN,TN,errors)
    skipped = {}   # rule -> set(modules) not yet ported to the core (pending migration)
    print(f"== drain-scan validation{tag} ==  wal-root={wal_root}")
    print(f"{'RULE':<5} {'LABEL':<5} {'FIRED':<6} {'EXPECT':<7} {'CELL':<5} FIXTURE")
    print("-" * 90)

    hard_error = False
    for rule, module, label, rel_path, contract, note in rows:
        engine = "semgrep" if module.endswith((".yaml", ".yml")) else "core"

        # Pending-migration SKIP: a core (.py) rule whose module was removed during the
        # Slither->core migration. Reported, not counted (not a regression).
        if engine == "core" and not os.path.isfile(os.path.join(REPO_ROOT, module)):
            print(f"{rule:<5} {label:<5} {'-':<6} {label:<7} {'SKIP':<5} pending core migration: {module}")
            skipped.setdefault(rule, set()).add(module)
            continue

        sol_path = os.path.join(wal_root, rel_path)
        pr = per_rule.setdefault(rule, dict(TP=0, FP=0, FN=0, TN=0, err=0))
        if not os.path.isfile(sol_path):
            print(f"{rule:<5} {label:<5} {'-':<6} {label:<7} {'ERR':<5} MISSING {rel_path}")
            pr["err"] += 1
            hard_error = True
            continue

        if engine == "core":
            try:
                det = load_core_detector(module)
            except Exception as exc:
                print(f"{rule:<5} {label:<5} {'-':<6} {label:<7} {'ERR':<5} detector load: {exc}")
                pr["err"] += 1
                hard_error = True
                continue
            count, err = run_core(sol_path, det, wal_root, contract=contract)
        else:
            yaml_path = os.path.join(REPO_ROOT, module)
            if not os.path.isfile(yaml_path):
                print(f"{rule:<5} {label:<5} {'-':<6} {label:<7} {'ERR':<5} MISSING rule {module}")
                pr["err"] += 1
                hard_error = True
                continue
            count, err = run_semgrep(yaml_path, sol_path, contract=contract)

        if err is not None:
            print(f"{rule:<5} {label:<5} {'-':<6} {label:<7} {'ERR':<5} compile: {err}  ({rel_path})")
            pr["err"] += 1
            hard_error = True
            continue

        fired = count > 0
        if label == "vuln":
            cell = "TP" if fired else "FN"
            pr["TP" if fired else "FN"] += 1
        else:  # safe
            cell = "FP" if fired else "TN"
            pr["FP" if fired else "TN"] += 1
        disp = rel_path + (f" :: {contract}" if contract else "")
        print(f"{rule:<5} {label:<5} {str(count):<6} {label:<7} {cell:<5} {disp}")

    # metrics
    def pr_metrics(tp, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        rec = tp / (tp + fn) if (tp + fn) else float("nan")
        if prec == prec and rec == rec and (prec + rec) > 0:  # not NaN and denom>0
            f1 = 2 * prec * rec / (prec + rec)
        else:
            f1 = float("nan")
        return prec, rec, f1

    print(f"\n== per-rule{tag} ==")
    gTP = gFP = gFN = gTN = gErr = 0
    fail = hard_error
    for rule in sorted(per_rule):
        d = per_rule[rule]
        gTP += d["TP"]; gFP += d["FP"]; gFN += d["FN"]; gTN += d["TN"]; gErr += d["err"]
        prec, rec, f1 = pr_metrics(d["TP"], d["FP"], d["FN"])
        status = "OK" if (d["FP"] == 0 and d["FN"] == 0 and d["err"] == 0) else "FAIL"
        if status == "FAIL":
            fail = True
        print(
            f"  {rule:<5} TP={d['TP']} FP={d['FP']} FN={d['FN']} TN={d['TN']} "
            f"err={d['err']}  P={prec:.3f} R={rec:.3f} F1={f1:.3f}  [{status}]"
        )

    if skipped:
        pend = ", ".join(f"{r}({len(m)})" for r, m in sorted(skipped.items()))
        print(f"\n  pending core migration (not counted): {pend}")

    oprec, orec, of1 = pr_metrics(gTP, gFP, gFN)
    print(f"\n== OVERALL{tag} ==")
    print(f"  TP={gTP} FP={gFP} FN={gFN} TN={gTN} errors={gErr}")
    print(f"  precision={oprec:.3f} recall={orec:.3f} F1={of1:.3f}")

    if fail:
        print("\n== VALIDATION: FAIL ==")
        return 1
    print("\n== VALIDATION: OK - every rule fires on vuln, silent on safe (0 FP/FN) ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
