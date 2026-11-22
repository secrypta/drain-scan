# 0-FP probe - precision discipline on real, unseen safe code

drain-scan's headline claim is **0 false positives on genuinely-safe code**. A linter that
cries wolf on canonical, audited implementations is worse than none - reviewers learn to ignore
it. This document is the plan for *proving* that claim continuously: a repeatable probe that runs
every rule's detector over a corpus of real, independent safe code and asserts **silence**.

It is engine-agnostic. drain-scan's analysis engine is moving to **our own analysis over the
solc compiler AST (no Slither)**; the probe below cares only about one observable - *did a rule
emit a finding on a file that is known-safe?* - so it survives the engine change unchanged. When
the solc-AST engine lands, only the *runner* (`validate/driver.py`) changes; the probe corpus,
the labels, and the pass bar do not.

## Two layers of precision evidence

1. **Safe anchors** (`validate/anchors.tsv`, `validate/anchors.holdout.tsv`, `label=safe`).
   One-or-few representative safe files per rule, wired into `validate/all.sh`. These are the
   *gate*: any FP here fails the build (DEV) and is reported (HOLDOUT). Necessary but narrow -
   a handful of files per rule.

2. **The 0-FP probe** (this plan). A *broad sweep*: run every detector over **whole real
   libraries** - not one hand-picked file but every contract in a vendored canonical codebase -
   and require zero findings. This catches precision regressions the few anchors miss (a detector
   that fires on some OZ contract we never anchored). It is the difference between "silent on the
   3 safe files we chose" and "silent on all of OpenZeppelin / Solady / Permit2 we ship".

The anchors answer *"does the rule stay silent on its designated safe counterpart?"*. The probe
answers *"does the rule stay silent on real code at large?"* - which is the honest precision
question a grant reviewer will ask.

## Probe corpus (all already vendored, public, attributed)

Real, audited, independent code already in the wallet-harness repo under
`fixtures/vendor/` (see `fixtures/vendor/PROVENANCE.md` for commits + licenses):

| corpus | path (under `$WAL_ROOT`) | license | stresses rules |
|--------|--------------------------|---------|----------------|
| OpenZeppelin (ERC20/ERC721/AccessControl/...) | `fixtures/vendor/oz/` | MIT | R1, R2, R3, R5, R6, R10 |
| Solady (ERC20/ERC721/ERC1271) | `fixtures/vendor/solady/` | MIT | R1, R2, R5, R6 |
| Uniswap Permit2 (AllowanceTransfer/SignatureTransfer) | `fixtures/vendor/permit2/` | MIT | R4, R5, R6 |

Plus the `c-safe-impl` tier of every vector (real-safe implementations, not toys) as a
secondary probe set. Every file here is **held out from detector tuning**: detectors are written
against the toy (`a`) and incident (`b`) tiers; the vendored safe code is unseen, so silence on
it is a genuine generalization result, not memorization.

**Boundary (§GRANITSA):** probe only PUBLIC, vendored/pinned code, fully offline, in Docker; no
live RPC, no live contracts. Every third-party file keeps its upstream attribution + license.

## Method

For each detector `D` and each file `F` in the probe corpus:

```
run D over F  ->  expected: 0 findings
                  any finding = a false-positive candidate -> triage
```

Mechanically this reuses the validation driver with a probe manifest instead of the anchor
manifest. Proposed runner (phase 2, once the solc-AST engine is in):

```
validate/zero_fp_probe.sh            # sweeps the vendored corpora, prints per-rule FP counts
WAL_ROOT=/path/to/wallet-harness validate/zero_fp_probe.sh
```

It emits, per rule: `<rule>  files=<n>  findings=<k>  -> PASS (k=0) | FP-CANDIDATES (k>0, list)`,
and exits non-zero if any rule has `k>0`. Output format mirrors `all.sh` so the two read as one
precision story.

## Triage workflow (what a probe hit means)

A probe finding is **not** automatically a detector bug - triage in this order:

1. **Is the flagged file actually safe for this rule?** If the vendored code genuinely contains
   the drain surface (rare, but possible in example/mock files), it is a true positive -
   re-label it as a `vuln` anchor, don't suppress.
2. **Is it a real false positive?** Then it is a **detector** defect. drain-scan's detector code
   is owned by tracks A/B/D - file the FP (rule id, file, line, why-safe) to them with a minimal
   repro; the fix is a detector change (a guard/dataflow refinement), **not** an anchor edit and
   **not** a blanket path suppression.
3. **Re-run** the probe after the fix; the file joins the safe corpus permanently.

This keeps precision honest: FPs are fixed in the analysis, never hidden by excluding the file.

## Pass bar

- **Every** rule: `findings = 0` over the whole probe corpus.
- A probe regression (any rule starts firing on previously-silent real code) **blocks release**,
  the same weight as a DEV-anchor FP.
- Reported alongside recall (the vuln anchors) so the benchmark shows both axes: *recall 1.0 on
  known incidents, precision 1.0 on real safe code*.

## Status / handoff

- **Now (phase 1):** plan + corpus identified; safe anchors extended with independent holdout
  safe code (Solady ERC721 -> R2; Solady ERC20 -> R1/R3; OZ ERC20Permit -> R5/R6; Solady ERC1271 ->
  R6; real Permit2 -> R4-vector). See `validate/anchors.holdout.tsv`.
- **Phase 2 (after the solc-AST foundation lands):** implement `validate/zero_fp_probe.sh` on the
  new driver, run it over the vendored corpora, triage any hits to A/B/D, and fold the per-rule FP
  line into `all.sh`'s report. Detector code stays with A/B/D; this track owns the corpus, the
  labels, the probe runner wiring, and this doc.
