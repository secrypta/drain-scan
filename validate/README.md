# drain-scan/validate - the methodology loop

This is the core rigor of drain-scan: **every rule is validated against executable PoC
fixtures** from the [`wallet-harness`](https://github.com/secrypta/wallet-harness) corpus.
For each rule, the loop runs its detector - our own analysis over the solc AST, no Slither -
over the labeled fixtures that anchor it and
asserts the rule **fires on every vulnerable anchor** and **stays silent on every safe anchor**
(0 false positives), then prints per-rule and overall precision/recall.

## Setup (once)

```bash
cd drain-scan
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
solc-select install 0.8.24          # the solc most fixtures compile with
solc-select install 0.8.17          # also needed: Uniswap Permit2 fixtures pin pragma 0.8.17
```

The fixtures are first-party (our own PoC code), so **no Docker is needed** - Docker in this
project is only ever for third-party code. The core compiles each fixture `.sol` directly with
`solc` as a subprocess (picking the solc version per-file by its `pragma`, not the surrounding
Foundry project, so `forge` is not required).

## Run

```bash
validate/run.sh                 # validate every rule in anchors.tsv (one combined report)
validate/run.sh R1              # validate only rule R1
validate/all.sh                 # full benchmark: per-rule + OVERALL P/R/F1, DEV and HOLDOUT
WAL_ROOT=/path/to/wallet-harness validate/all.sh   # point at a wallet-harness checkout
```

`WAL_ROOT` defaults to `~/wal` (an example path - point it at wherever you cloned
`secrypta/wallet-harness`). `SOLC_VERSION` defaults to `0.8.24`.

### `all.sh` - the scanner benchmark (drain-scan ⇄ drain-bench)

`all.sh` runs **every** rule's detector - core (`detectors/*.py`, our solc-AST analysis) and
semgrep (`semgrep/*.yaml`, a syntactic subset), dispatched by the detector extension in each
anchor row - over its labeled
anchors and prints per-rule and OVERALL **precision / recall / F1**, reported **separately** for:

- **DEV** anchors (`validate/anchors.tsv`) - the fixtures the rules were written against;
- **HOLDOUT** anchors (`validate/anchors.holdout.tsv`) - independent fixtures, held out to
  measure generalization.

The dev/holdout split mirrors the [`drain-bench`](https://github.com/secrypta/wallet-harness)
dataset manifest's `split` column - this is the drain-scan ⇄ drain-bench link. HOLDOUT is
reported as "pending" until that corpus is merged (adding a holdout anchor is a one-line row;
no code change). `all.sh` exits non-zero if DEV fails; set `STRICT_HOLDOUT=1` to also fail on
HOLDOUT regressions once holdout anchors exist.

## How it fits together

```
validate/anchors.tsv   rule <-> labeled fixture map (rule, detector, vuln|safe, path, note)
validate/driver.py     loads each rule's core detector, runs it over each anchor's solc AST, scores P/R
validate/run.sh        venv + solc wrapper around driver.py
detectors/*.py         the core detectors (our Detector subclasses over the solc AST; no Slither)
```

`anchors.tsv` is the single source of truth tying a rule to the PoC it must catch and the
safe code it must not flag. Adding a rule = add its `detectors/<rule>.py` and its anchor rows;
`run.sh` then validates it with no code change. Exit code is non-zero on any false
positive/negative or compile error, so this doubles as CI.

## For dependent tracks (C/D)

Build on `validate/run.sh` as the gate: a new rule or a new safe anchor is "done" only when
`run.sh` stays green (vuln fires, safe silent, 0 FP/FN). Point `WAL_ROOT` at your
wallet-harness checkout; detectors load from `detectors/` by path, so no packaging/install of
the detectors themselves is required for the loop.

## Continuous integration

`.github/workflows/validate.yml` runs this whole loop from a clean machine on every push / PR,
so the reproducibility claim is checked automatically, not just locally. It creates the venv
from `requirements.txt`, installs both pinned compilers (`0.8.24` + `0.8.17`), checks out the
public `wallet-harness` corpus as `WAL_ROOT`, then runs:

- `validate/zero_fp_probe.sh` - **0 false positives** on the real vendored safe corpus;
- `validate/all.sh` with `STRICT_HOLDOUT=1` - **precision = recall = 1.0** on DEV *and* HOLDOUT;
- a `./scan` smoke - a known-vulnerable fixture reports findings (exit 1), a known-safe one
  stays silent (exit 0).

Any false positive/negative, precision/recall regression, or wrong exit code fails the build.
