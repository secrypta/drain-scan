#!/usr/bin/env python3
"""drain-scan scanner - `scan <path>`.

Phase-2 UX layer: run the drain-scan rule set over a target (a .sol file or a directory of
.sol files) and print ONE unified report. It aggregates the hits from the drain-scan CORE
detectors (solc AST, no Slither) and, when present, the Semgrep rules, and joins each hit to
the rule registry (../rules.tsv) so every finding reads the same way regardless of engine:

    rule_id - vector - severity - engine - location - message - poc_fixture - fix

The registry is the single source of enrichment (owner: track D); detectors / Semgrep rules
only detect. A core hit is matched to its rule by the registry row that names its detector
module; a Semgrep hit by its rule id. Rules whose detector is not yet implemented ('-') or
not yet ported to the core are skipped at scan time but still enrich a hit if one appears.

Usage:
    scan <path> [--format pretty|json|sarif|html] [--rules <rules.tsv>] [--allow-paths <dir>]
                [--no-fail] [--color auto|always|never]
    scan --list-rules | --explain R<N> | --version    (introspection; no path needed)
Exit code: non-zero if any finding (so it gates CI), unless --no-fail. See `scan --help`.
"""
import argparse
import glob
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core import compile as core_compile  # noqa: E402
from core.ast import Unit  # noqa: E402
from core.detector import Detector  # noqa: E402

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

# Pre-release version; the public tag is assigned at release (see PUBLISH.md). `--version` also
# prints the live rule count read from the registry, so it never drifts from what actually ships.
_VERSION = "0.1.0"

# Display name is a WORKING NAME (README: final public name set at publication). It is centralized
# here so a rename is one edit for all user-facing output (pretty / --version / --list-rules / SARIF
# driver / HTML); the docs are swept separately. `scan` (the command / argv[0]) is unaffected.
_TOOL_NAME = "drain-scan"
_TOOL_URL = "https://github.com/secrypta/drain-scan"


# ------------------------------- registry -------------------------------

def load_registry(path):
    """Parse rules.tsv -> {rule_id: row-dict}. Columns are the header row."""
    rules = {}
    header = None
    with open(path) as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if header is None:
                header = parts
                continue
            row = dict(zip(header, parts))
            rules[row["rule_id"]] = row
    if not rules:
        raise ValueError(f"no rules parsed from {path}")
    return rules


def load_core_detector(module_rel):
    module_path = os.path.join(REPO_ROOT, module_rel)
    if not os.path.isfile(module_path):
        raise FileNotFoundError(module_rel)
    spec = importlib.util.spec_from_file_location(
        "drain_scan_" + os.path.basename(module_path).replace(".", "_"), module_path
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
    return dets[0]()


# ------------------------------- engines -------------------------------

_FRAMEWORK_MARKERS = ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js")


def _load_core_rules(rules):
    """Instantiate every registry rule whose detector module is a core .py that exists.
    Returns [(rule_id, detector_instance)]. Modules still '-' or not yet ported are skipped."""
    loaded = []
    for rid, row in rules.items():
        mod = row.get("detector_module", "-")
        if not mod or mod == "-" or not mod.endswith(".py"):
            continue
        try:
            loaded.append((rid, load_core_detector(mod)))
        except FileNotFoundError:
            # not yet ported to the core (pending migration) - skip quietly
            continue
        except Exception as exc:
            print(f"warning: could not load detector {mod}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    return loaded


def _core_covered_rule_ids(rules):
    """Rule ids that have a loadable core detector. The core AST analysis is authoritative for
    these rules; the Semgrep variant (R2'/R6'/R10') is a syntactic CROSS-CHECK only (it cannot
    see access-control / data-flow), so it must not originate a verdict the core suppressed -
    e.g. the governance/guardian-gated R10 safe upgrades the core correctly stays silent on.
    Semgrep still contributes verdicts for any rule with no core detector (none today), and is
    still validated independently rule-by-rule in validate/ (anchors)."""
    return {rid for rid, _ in _load_core_rules(rules)}


def _targets_for(path):
    """A single .sol -> [it]; a directory -> every .sol under it (each compiled on its own)."""
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        targets = sorted(glob.glob(os.path.join(path, "**", "*.sol"), recursive=True))
        if not targets:
            print(f"error: no .sol files under {path}", file=sys.stderr)
            raise SystemExit(2)
        return targets
    print(f"error: not a .sol file or directory: {path}", file=sys.stderr)
    raise SystemExit(2)


def run_core(path, rules, allow_paths):
    """Compile each target with solc and run every loaded core detector.

    Returns (findings, skipped): `findings` is the list of enriched hits; `skipped` lists files
    that did NOT compile standalone ({file, error}). Skipped files are surfaced in the report,
    never silently dropped - a linter that quietly skips a file it cannot build gives a false
    "clean", which is worse than a visible coverage gap.

    Project note: the core compiles .sol files directly with solc (framework-aware project
    resolution is a later migration step); a framework project is scanned as its .sol files."""
    detectors = _load_core_rules(rules)
    if not detectors:
        return [], []
    targets = _targets_for(path)

    # Default solc --allow-paths: a DIRECTORY scan allows the scanned dir root, so intra-tree and
    # vendored relative imports (e.g. ../../vendor/oz/...) resolve across files; a single file
    # allows its own directory. An explicit --allow-paths always wins. (core.compile already
    # picks the solc version per file by its pragma, so mixed-pragma trees are fine.)
    default_ap = os.path.abspath(path) if os.path.isdir(path) \
        else os.path.dirname(os.path.abspath(path))

    findings = []
    skipped = []
    for target in targets:
        ap = allow_paths or default_ap or "."
        try:
            data = core_compile.compile_source(target, allow_paths=ap)
            unit = Unit.from_compile(data)
        except Exception as exc:
            first = (str(exc).splitlines() or [type(exc).__name__])[0]
            skipped.append({"file": target, "error": first[:200]})
            print(f"warning: could not compile/analyze {target}: {first[:200]}", file=sys.stderr)
            continue
        for rid, det in detectors:
            for f in det.detect(unit):
                findings.append(_enrich(rid, rules[rid], "core", f.location(),
                                        rules[rid].get("summary") or f.message))
    if skipped and len(targets) == 1:
        # a single explicit target that failed to compile is a hard error, not "clean"
        raise SystemExit(2)
    return findings, skipped


def run_semgrep(path, rules, semgrep_dir):
    """Run Semgrep rules (if any exist and semgrep is installed). No-op otherwise."""
    rule_files = glob.glob(os.path.join(semgrep_dir, "*.yml")) + \
        glob.glob(os.path.join(semgrep_dir, "*.yaml"))
    if not rule_files:
        return []
    if not shutil.which("semgrep"):
        print("warning: semgrep rules present but `semgrep` not installed - skipping.",
              file=sys.stderr)
        return []
    try:
        out = subprocess.run(
            # --jobs 1: cap semgrep to one worker (it otherwise spawns one per core,
            # natively outside Docker; parallel scans then saturate every core).
            ["semgrep", "scan", "--jobs", "1", "--config", semgrep_dir, "--json", "--quiet", path],
            capture_output=True, text=True, check=False,
        )
        data = json.loads(out.stdout or "{}")
    except Exception as exc:  # semgrep failure must not crash the whole scan
        print(f"warning: semgrep run failed ({exc}); continuing with core detectors only.",
              file=sys.stderr)
        return []
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        rid = _semgrep_rule_id(meta.get("drain-scan-rule"), r.get("check_id", ""), rules)
        row = rules.get(rid) if rid else None
        loc = f"{r.get('path','?')}:{(r.get('start',{}) or {}).get('line','?')}"
        msg = (row or {}).get("summary") or extra.get("message", "semgrep hit")
        findings.append(_enrich(rid or "?", row or {}, "semgrep", loc, msg))
    return findings


def _normalize_rule_key(value):
    """'R10prime' / "R10'" / 'R10′' -> 'R10'; otherwise upper-cased as-is."""
    if not value:
        return None
    v = value.strip().upper().replace("PRIME", "")
    return v.rstrip("'′ ").strip() or None


def _semgrep_rule_id(meta_rule, check_id, rules):
    """Map a semgrep hit to a drain-scan rule_id. Canonical source is the rule's
    `metadata.drain-scan-rule` field (e.g. 'R2', 'R6', 'R10prime'); fall back to a token in
    the check_id. The semgrep R10' cross-check normalizes to the registry's R10 row."""
    key = _normalize_rule_key(meta_rule)
    if key and key in rules:
        return key
    tokens = check_id.replace("/", ".").replace("-", ".").split(".")
    upper = {t.upper() for t in tokens}
    for rid in rules:
        if rid.upper() in upper:
            return rid
    return None


def _enrich(rid, row, engine, location, message):
    return {
        "rule_id": rid,
        "vector": row.get("vector", "?"),
        "severity": row.get("severity", "?"),
        "engine": engine,
        "location": location,
        "message": message,
        "poc_fixture": row.get("poc_fixture", "?"),
        "fix": row.get("fix_doc", "?"),
    }


# ------------------------------- color (TTY-aware) -------------------------------

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m", "cyan": "\033[36m",
}
# severity label -> style; drain-risk rating -> style.
_SEV_STYLE = {"high": "red", "medium": "yellow", "low": "dim"}
_RATING_STYLE = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "CLEAN": "green"}


def _want_color(mode):
    """Resolve --color {auto,always,never}. 'auto' colors only when stdout is a TTY and NO_COLOR
    is unset (https://no-color.org) - so piped / redirected output and json/sarif stay plain."""
    if mode == "never":
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _painter(enabled):
    """Return paint(text, *styles): wrap `text` in the ANSI styles, or return it unchanged when
    color is disabled. Pad fields BEFORE painting so column alignment is unaffected by the codes."""
    if not enabled:
        return lambda text, *styles: text

    def paint(text, *styles):
        pre = "".join(_ANSI.get(s, "") for s in styles)
        return f"{pre}{text}{_ANSI['reset']}" if pre else text
    return paint


def _rid_num(rid):
    """Sort key so R2 < R10 (numeric, not lexical). Non-numeric ids sort last."""
    try:
        return int(rid[1:])
    except (ValueError, IndexError):
        return 1 << 30


# ------------------------------- output -------------------------------

def _sev_key(f):
    return _SEV_ORDER.get(f["severity"].split("/")[0], 9)


_RATING_BY_RANK = {0: "HIGH", 1: "MEDIUM", 2: "LOW"}


def compute_rating(findings):
    """Per-target DRAIN-risk rating: the HIGHEST severity among the rules that fired, or CLEAN
    if none did. Severity values are read from the rule registry (rules.tsv, owner: track D) via
    _enrich - never hard-coded here - so the scale (high/medium/low) tracks whatever D sets.

    This is a *drain-risk* rating within this scanner's scope, NOT a general security audit;
    CLEAN means no drain surface was flagged, not that the contract is safe overall."""
    if not findings:
        return "CLEAN"
    best = min(_SEV_ORDER.get(f["severity"].split("/")[0], 9) for f in findings)
    return _RATING_BY_RANK.get(best, "UNKNOWN")


def _append_skipped(lines, skipped):
    """Report files that did not compile standalone - a coverage gap, shown, never hidden."""
    if not skipped:
        return
    lines.append("")
    lines.append(f"skipped: {len(skipped)} file(s) did not compile standalone and were NOT "
                 "scanned")
    lines.append("  (a coverage gap, not a clean result - these files were not analyzed):")
    for s in skipped[:20]:
        lines.append(f"  - {s['file']}  ({s['error']})")
    if len(skipped) > 20:
        lines.append(f"  ... and {len(skipped) - 20} more")
    lines.append("  tip: pass --allow-paths <project-root> so imports resolve, or list all via "
                 "--format json.")


def render_pretty(findings, path, skipped=None, color=False):
    skipped = skipped or []
    paint = _painter(color)
    lines = []
    rating = compute_rating(findings)
    rating_lbl = paint(f"RATING: {rating}", "bold", _RATING_STYLE.get(rating, ""))
    if rating == "CLEAN":
        lines.append(f"{rating_lbl}   (no drain surface flagged - not a general safety guarantee)")
    else:
        lines.append(f"{rating_lbl}   (drain-risk - this scanner's scope, not a general audit)")
    lines.append("")
    lines.append(f"{_TOOL_NAME} - {len(findings)} finding(s) in {path}\n")
    if not findings:
        lines.append("  no drain surfaces flagged by the current rule set.")
        lines.append("  (note: a clean scan is not a security guarantee - see RULES.md scope.)")
        _append_skipped(lines, skipped)
        return "\n".join(lines)
    by_vector = {}
    for f in findings:
        by_vector.setdefault(f["vector"], []).append(f)
    for vector in sorted(by_vector):
        lines.append(paint(f"== {vector} ==", "bold", "cyan"))
        for f in sorted(by_vector[vector], key=_sev_key):
            sev = f["severity"].split("/")[0]
            sev_lbl = paint(f"{f['severity'].upper():<11}", _SEV_STYLE.get(sev, ""))
            lines.append(f"  [{paint(f['rule_id'], 'bold')}] {sev_lbl} {f['engine']}  {f['location']}")
            lines.append(f"       {f['message']}")
            lines.append(f"       PoC : {f['poc_fixture']}")
            lines.append(f"       fix : {f['fix']}")
        lines.append("")
    # severity tally
    tally = {}
    for f in findings:
        tally[f["severity"]] = tally.get(f["severity"], 0) + 1
    summary = "  ".join(f"{k}={v}" for k, v in sorted(tally.items()))
    lines.append(f"summary: {len(findings)} finding(s)  [{summary}]")
    _append_skipped(lines, skipped)
    return "\n".join(lines)


_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _split_location(loc):
    """'file:line:sym' / 'file:line' / 'file' / '?' -> (file|None, line|None)."""
    if not loc or loc == "?":
        return None, None
    import re
    m = re.match(r"^(.*?):(\d+)(?::.*)?$", loc)
    if m:
        return m.group(1), int(m.group(2))
    return loc, None


def render_sarif(findings, path):
    """Minimal valid SARIF 2.1.0 - one run, one tool driver, result per finding with
    ruleId / message / physical location. Rule objects are emitted for the rules that fired."""
    rules_seen = {}
    results = []
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": f"{rid}-{f['vector']}",
                "shortDescription": {"text": f["message"]},
                "properties": {
                    "vector": f["vector"],
                    "severity": f["severity"],
                    "poc_fixture": f["poc_fixture"],
                    "fix": f["fix"],
                },
            }
        uri, line = _split_location(f["location"])
        phys = {"artifactLocation": {"uri": uri or path}}
        if line is not None:
            phys["region"] = {"startLine": line}
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f["severity"].split("/")[0], "warning"),
            "message": {"text": f"[{rid}] {f['message']} (vector: {f['vector']}; fix: {f['fix']})"},
            "locations": [{"physicalLocation": phys}],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": _TOOL_NAME,
                "informationUri": _TOOL_URL,
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


_HTML_CSS = """\
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
  background:#f6f7f9;color:#1b1f24}
@media(prefers-color-scheme:dark){body{background:#0f1115;color:#e6e9ef}
  .card,.head{background:#181b21!important;border-color:#2a2f37!important}
  .loc,code{background:#22262e!important}}
.wrap{max-width:900px;margin:0 auto;padding:28px 20px 56px}
.head{background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:20px 22px;margin-bottom:22px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#6b7280;font-size:13px;word-break:break-all}
.badge{display:inline-block;padding:3px 12px;border-radius:999px;font-weight:700;font-size:13px;
  letter-spacing:.3px;color:#fff;margin:10px 8px 2px 0}
.b-high{background:#c0392b}.b-medium{background:#c77d12}.b-low{background:#2b7cb3}.b-clean{background:#1f9254}
.tally{color:#6b7280;font-size:13px;margin-top:6px}
.vec{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;
  margin:24px 0 10px}
.card{background:#fff;border:1px solid #e3e6ea;border-left-width:4px;border-radius:9px;
  padding:14px 16px;margin:10px 0}
.card.s-high{border-left-color:#c0392b}.card.s-medium{border-left-color:#c77d12}.card.s-low{border-left-color:#2b7cb3}
.rid{font-weight:700}
.pill{font-size:11px;font-weight:700;padding:1px 8px;border-radius:999px;color:#fff;margin-left:6px}
.p-high{background:#c0392b}.p-medium{background:#c77d12}.p-low{background:#2b7cb3}
.eng{color:#6b7280;font-size:12px;margin-left:6px}
.loc{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  background:#f1f3f5;border-radius:6px;padding:4px 7px;margin:7px 0;word-break:break-all}
.msg{margin:6px 0}
.meta{font-size:12.5px;color:#4b5563;margin-top:4px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f1f3f5;border-radius:4px;padding:1px 5px}
.skip{margin-top:26px;border:1px dashed #c8ccd2;border-radius:9px;padding:12px 15px;font-size:13px;color:#4b5563}
.foot{margin-top:30px;color:#9aa1ab;font-size:12px;border-top:1px solid #e3e6ea;padding-top:14px}
"""


def _esc(s):
    import html as _h
    return _h.escape("" if s is None else str(s))


def render_html(findings, path, skipped=None):
    """Self-contained HTML report (inline CSS, no external assets, light/dark aware). Same data as
    the pretty/json views; nice to open or share. All dynamic text is HTML-escaped."""
    skipped = skipped or []
    rating = compute_rating(findings)
    r_low = rating.lower()
    tally = {}
    for f in findings:
        tally[f["severity"]] = tally.get(f["severity"], 0) + 1
    tally_str = "  ".join(f"{_esc(k)}={v}" for k, v in sorted(tally.items())) or "none"

    out = ["<!doctype html><html lang=en><head><meta charset=utf-8>",
           "<meta name=viewport content='width=device-width,initial-scale=1'>",
           f"<title>{_esc(_TOOL_NAME)} report</title>", f"<style>{_HTML_CSS}</style></head><body><div class=wrap>"]
    out.append("<div class=head>")
    out.append(f"<h1>{_esc(_TOOL_NAME)} report</h1>")
    out.append(f"<div class=sub>{_esc(path)}</div>")
    out.append(f"<span class='badge b-{r_low}'>RATING: {_esc(rating)}</span>")
    scope = ("no drain surface flagged - not a general safety guarantee" if rating == "CLEAN"
             else "drain-risk within this scanner's scope, not a general audit")
    out.append(f"<div class=tally>{len(findings)} finding(s) - {_esc(scope)}</div>")
    if findings:
        out.append(f"<div class=tally>severity: {tally_str}</div>")
    out.append("</div>")  # head

    by_vector = {}
    for f in findings:
        by_vector.setdefault(f["vector"], []).append(f)
    for vector in sorted(by_vector):
        out.append(f"<div class=vec>{_esc(vector)}</div>")
        for f in sorted(by_vector[vector], key=_sev_key):
            sev = f["severity"].split("/")[0]
            out.append(f"<div class='card s-{_esc(sev)}'>")
            out.append(f"<span class=rid>[{_esc(f['rule_id'])}]</span>"
                       f"<span class='pill p-{_esc(sev)}'>{_esc(f['severity'].upper())}</span>"
                       f"<span class=eng>{_esc(f['engine'])}</span>")
            out.append(f"<span class=loc>{_esc(f['location'])}</span>")
            out.append(f"<div class=msg>{_esc(f['message'])}</div>")
            out.append(f"<div class=meta>PoC: <code>{_esc(f['poc_fixture'])}</code></div>")
            out.append(f"<div class=meta>fix: <code>{_esc(f['fix'])}</code></div>")
            out.append("</div>")
    if not findings:
        out.append("<p>No drain surfaces flagged by the current rule set. "
                   "A clean scan is not a security guarantee - see RULES.md scope.</p>")

    if skipped:
        out.append("<div class=skip>")
        out.append(f"<b>skipped: {len(skipped)} file(s)</b> did not compile standalone and were NOT "
                   "scanned (a coverage gap, not a clean result):<br>")
        for s in skipped[:20]:
            out.append(f"- <code>{_esc(s['file'])}</code> ({_esc(s['error'])})<br>")
        if len(skipped) > 20:
            out.append(f"... and {len(skipped) - 20} more<br>")
        out.append("tip: pass <code>--allow-paths &lt;project-root&gt;</code> so imports resolve.")
        out.append("</div>")

    out.append(f"<div class=foot>generated by {_esc(_TOOL_NAME)} {_esc(_VERSION)} - "
               "static wallet-drain linter - a clean scan is not a general security audit "
               "(see RULES.md)</div>")
    out.append("</div></body></html>")
    return "\n".join(out)


# ------------------------------- rule introspection (no scan) -------------------------------

def cmd_list_rules(rules, color=False):
    """One line per rule: id, severity, vector, summary. For `scan --list-rules`."""
    paint = _painter(color)
    lines = [paint(f"{_TOOL_NAME} - {len(rules)} rules", "bold"), ""]
    for rid in sorted(rules, key=_rid_num):
        row = rules[rid]
        sev = row.get("severity", "?")
        rid_f = paint(f"{rid:<4}", "bold")
        sev_f = paint(f"{sev.upper():<7}", _SEV_STYLE.get(sev, ""))
        lines.append(f"  {rid_f}  {sev_f}  {row.get('vector', '?'):<22}  {row.get('summary', '')}")
    lines.append("")
    lines.append("  details: scan --explain R<N>   (e.g. scan --explain R13)")
    return "\n".join(lines)


def cmd_explain(rules, rid_arg, color=False):
    """Full registry detail for one rule. Returns the text, or None if the id is unknown."""
    paint = _painter(color)
    rid = rid_arg.strip().upper()
    if not rid.startswith("R"):
        rid = "R" + rid
    row = rules.get(rid)
    if not row:
        return None
    sev = row.get("severity", "?")
    out = [
        paint(f"{rid} - {row.get('vector', '?')}", "bold"),
        "",
        f"  severity : {paint(sev.upper(), _SEV_STYLE.get(sev, ''))}",
        f"  engine   : {row.get('engine', '?')}",
        f"  detector : {row.get('detector_module', '?')}",
        f"  PoC      : {row.get('poc_fixture', '?')}",
        f"  fix / doc: {row.get('fix_doc', '?')}",
        "",
        f"  {row.get('summary', '')}",
    ]
    return "\n".join(out)


_EPILOG = """\
examples:
  scan Wallet.sol                     scan one file (pretty; colored on a terminal)
  scan ./contracts --format json      scan a whole tree, machine-readable output
  scan Wallet.sol --allow-paths .     resolve vendored imports from this root
  scan --list-rules                   list every rule (id / severity / vector)
  scan --explain R13                  show one rule in full (PoC + fix pointer)

exit codes:
  0  clean - no drain surface flagged (or --no-fail)
  1  one or more findings reported (so `scan` gates CI)
  2  usage error, or a single target that did not compile

color: auto by default (only on a terminal); honours NO_COLOR and --color never/always.
A clean scan is NOT a general security guarantee - see RULES.md (Scope & honesty)."""


def main():
    ap = argparse.ArgumentParser(
        prog="scan", description=f"{_TOOL_NAME} - unified wallet-drain static scanner (rules R1-R15)",
        epilog=_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", nargs="?",
                    help="a .sol file or a directory of .sol files to scan")
    ap.add_argument("--format", choices=["pretty", "json", "sarif", "html"], default="pretty",
                    help="output format (default: pretty; html = self-contained report)")
    ap.add_argument("--rules", default=os.path.join(REPO_ROOT, "rules.tsv"),
                    help="rule registry TSV (default: bundled rules.tsv)")
    ap.add_argument("--allow-paths", default=None, help="solc --allow-paths for single-file scans")
    ap.add_argument("--no-fail", action="store_true", help="exit 0 even if findings are reported")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colorize pretty output (default: auto - a terminal only)")
    ap.add_argument("--version", action="store_true", help="print version + rule count and exit")
    ap.add_argument("--list-rules", action="store_true", help="list every rule and exit")
    ap.add_argument("--explain", metavar="R<N>", default=None,
                    help="print one rule's registry detail and exit (e.g. --explain R13)")
    args = ap.parse_args()

    color = _want_color(args.color)
    rules = load_registry(args.rules)

    # --- rule introspection (no scan; no path needed) ---
    if args.version:
        rng = ""
        ids = sorted(rules, key=_rid_num)
        if ids:
            rng = f", {ids[0]}-{ids[-1]}"
        print(f"{_TOOL_NAME} {_VERSION}  ({len(rules)} rules{rng})")
        return 0
    if args.list_rules:
        print(cmd_list_rules(rules, color=color))
        return 0
    if args.explain is not None:
        text = cmd_explain(rules, args.explain, color=color)
        if text is None:
            print(f"error: unknown rule '{args.explain}'. Try: scan --list-rules", file=sys.stderr)
            return 2
        print(text)
        return 0

    # --- scan ---
    if not args.path:
        ap.error("a path is required to scan (or use --list-rules / --explain / --version)")
    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    findings, skipped = run_core(args.path, rules, args.allow_paths)
    # Core is authoritative over the syntactic Semgrep cross-check: keep a Semgrep hit only for
    # a rule that has no core detector (today: none). This stops a syntactic variant (e.g. R10')
    # from raising a verdict the precise core detector suppressed - such as an authority-gated
    # safe upgrade. Semgrep stays validated rule-by-rule in validate/ (anchors), unaffected.
    _core_covered = _core_covered_rule_ids(rules)
    findings += [f for f in run_semgrep(args.path, rules, os.path.join(REPO_ROOT, "semgrep"))
                 if f.get("rule_id") not in _core_covered]

    if args.format == "json":
        print(json.dumps({"path": args.path, "rating": compute_rating(findings),
                          "findings": findings, "count": len(findings),
                          "skipped": skipped, "skipped_count": len(skipped)}, indent=2))
    elif args.format == "sarif":
        print(render_sarif(findings, args.path))
    elif args.format == "html":
        print(render_html(findings, args.path, skipped))
    else:
        print(render_pretty(findings, args.path, skipped, color=color))

    if findings and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
