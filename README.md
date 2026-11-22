# drain-scan

> Narrow by design.

A **static linter for drain surfaces in smart-contract wallets and accounts** - smart
wallets, ERC-4337 (account-abstraction) accounts, EIP-7702 delegates, and multisigs. It
flags the code-level patterns through which wallet funds get drained: unbounded approvals,
lingering allowances, unsafe signature/permit validation, controlled delegatecall,
allowlist-less account execution, unpinned external-code trust, and ungoverned upgradeability.

It is **not** a general smart-contract analyzer. It scans wallet/account code only, which is
what keeps its rules sharp and its false positives low. The wallet-UX / transaction-time side
of drains (phishing sites, address poisoning, blind-sign prompts) is out of scope - that is
handled by wallet transaction-screening tools, and is not visible in contract code.

## Quickstart

```bash
# 1. one-time setup - a venv with solc + semgrep (no Slither; MIT)
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
solc-select install 0.8.24 && solc-select use 0.8.24

# 2. scan a contract (a .sol file or a directory of them)
./scan path/to/Wallet.sol

# 3. explore the rules - no target needed
./scan --list-rules          # every rule: id / severity / vector
./scan --explain R13         # one rule in full (PoC fixture + fix pointer)
```

Each finding prints its rule, severity, location, the executable PoC fixture that proves it,
and a fix pointer; `scan` exits non-zero when anything is flagged, so it drops straight into
CI. Output is colorized on a terminal (honours `NO_COLOR` / `--color`); `--format json|sarif|html`
gives machine-readable or shareable reports. See [`docs/examples/`](docs/examples) for real runs.
A clean scan is **not** a general security guarantee - see *Scope & honesty*.

## What makes it different
Every rule is **backed by an executable proof-of-concept** of a real drain (from the
[`wallet-harness`](https://github.com/secrypta/wallet-harness) corpus) and **validated at zero
false positives against genuinely-safe real code**. The loop *static rule ⇄ executable PoC ⇄
labeled vuln/safe benchmark* is the core idea: every finding is proven, and every rule is
proven not to fire on safe code. The ground-truth behind that claim - the real incidents the
rules re-discover and the real safe code they stay silent on - is laid out next.

## Validation & ground-truth evidence
Every rule is anchored to a **real, publicly-documented drain** and proven not to fire on
**genuinely-safe real code**. That is the project's central claim, so it comes first.

### Real incidents the rules re-discover
Each entry is a minimized, offline **MIT reproduction** of a public incident (no third-party code
copied). The provenance - transaction / amount / date - is recorded **verbatim** in each fixture's
`PROVENANCE.md` in the [`wallet-harness`](https://github.com/secrypta/wallet-harness) corpus. The
**holdout** incidents were added *after* the harness interface froze (`v0.1`), but they were not
hidden from rule authors: R11-R15 and several false-positive fixes were written while the holdout
was in the repo, and some holdout fixtures are rule anchors. Read a holdout hit as recall on a
separately sourced fixture, not as recall on code no rule author ever saw.

| Incident | Date | Reported loss | Drain mechanism | Split |
|---|---|---|---|---|
| Parity multisig (first hack) | 2017-07-19 | ~153,037 ETH (~$30M) across wallets | delegatecall-reachable unguarded `initWallet` seizes ownership -> `execute` drains | holdout |
| Audius governance takeover | 2022-07-23 | 18,564,497 AUDIO (~$6M nominal, ~705 ETH realized) | re-callable proxy `initialize` installs an attacker controller -> treasury drain | holdout |
| Tornado Cash governance | 2023-05-21 | TORN locked in governance seized (~1.2M forged votes) | CREATE2-metamorphic proposal + single-key pointer swap, no timelock/guardian | holdout |
| NFTTrader.org | 2023-12-16 | ~$3M | reentrant mid-settlement callback re-reads counterparty -> victim's standing `setApprovalForAll` drained (CEI violation) | holdout |
| Inferno Drainer (EIP-7702 batch) | 2025-05-24 | ~$146,551 | a 7702-delegated account runs an attacker-supplied multi-asset batch with no allow-list | holdout |
| Lixir forged permit | 2026-06-25 | ~$12.3K realizable | `permit` accepts any signature with nonzero `ecrecover` (no `recovered == owner`, no domain/nonce binding) | holdout |
| Bybit cold-wallet | 2025-02-21 | ~$1.46B | Safe `execTransaction` `operation` flag flipped to delegatecall -> `masterCopy` pointer seized | dev |
| PAID Network | 2021-03-05 | ~59.47M PAID minted (~$3M realized) | single-key proxy upgrade (no timelock/guardian) swaps in a mint-capable implementation | dev |

Proof level is recorded per fixture and honest about its limits: some reproductions are
**incident-level** (pinned public tx + addresses - e.g. Parity, Audius, Tornado Cash, NFTTrader,
Lixir); others are **mechanism / class-level** where full calldata was never public (e.g. Bybit,
Inferno Drainer), and there the dollar figures are the reported/representative ones, not an
on-chain replay.

### The 0-false-positive invariant
0 false positives on genuinely-safe real code is a **hard ship requirement**, held *above* recall.
Each rule is proven silent across a corpus of real safe implementations - vendored OpenZeppelin,
Solady and Uniswap Permit2 at their canonical versions - and a rule that fires on any of them is
not shipped. The guiding invariant is **precision 1.0 / 0 FP on the labeled safe corpus**: a
design constraint, not a marketing number.

### Honest non-fits (maturity, not weakness)
Where a real incident cannot be caught without a false positive on canonical safe code, drain-scan
documents it as a **non-fit** rather than widening a rule and breaking the 0-FP invariant:

- **Parity (2017)** is a non-fit for the principled controlled-delegatecall rule - its proxy
  delegatecalls a *fixed* library, so flagging it would require firing on every legitimate proxy
  (EIP-1167 / UUPS). It is instead caught by the unprotected-initializer rule (the root cause).
- **SquidMulticall** (2026-04-07, ~$517K across 5 chains) and **Pennysia Settlement** (2026-11-12)
  are pure arbitrary executors that hold no approval in their own code - the custody fact is
  off-contract - so the static layer cannot tell them apart from a canonical allow-listed executor
  without false-positiving on OpenZeppelin Timelock / Permit2.
- **Wormhole uninitialized implementation** (2022-02-24, $10M whitehat reward) turned on a
  deploy-time fact (the implementation was left uninitialized), absent from the contract's own
  guarded source.

### Off-chain boundary
Fake-airdrop lures, address poisoning, blind-signing prompts and wallet-UI phishing are **out of
scope by design**: they are transaction-time / UX attacks, not decidable from contract source.
That boundary is what keeps the rules sharp and the false-positive rate at zero.

### Results snapshot
drain-scan scored **as a tool** against the `wallet-harness` labeled corpus, the same way as every
baseline (one verdict per subject, scored by `bench/score.sh`). Full tables and the per-tool
comparison - honestly including where the narrow scope ends - live in [`BENCHMARK.md`](BENCHMARK.md).
Headline figures (one authoritative run, rules R1-R15):

| Split | Labeled fixtures | TP | FP | FN | TN | MISS | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| all (dev + holdout) | 155 | 35 | **0** | 33 | 83 | 4 | **1.000** | 0.515 | 0.680 |
| holdout (post-freeze) | 94 | 18 | **0** | 22 | 52 | 2 | **1.000** | 0.450 | 0.621 |

**Precision 1.0 is a design constraint, not an outcome.** 0 false positives on the labeled safe
corpus is a hard ship requirement, held *above* recall. Recall is deliberately narrow: drain-scan
fires only on code-decidable wallet-drain surfaces and stays silent on off-chain / out-of-scope
vectors - see the *coverage boundary* in [`BENCHMARK.md`](BENCHMARK.md) for what each false negative
is. It is the precision-first **static** companion to the full-coverage dynamic `wal` harness.

> **Rule-anchor sanity gate - not an independent recall.** Separately, `validate/all.sh` asserts
> every rule fires on its own labeled vuln anchor and stays silent on its safe anchor: **DEV** 35
> fixtures / 53 rule-anchor evals and **HOLDOUT** 18 / 22, all at precision/recall/F1 = 1.000. This
> is a **tuned** gate (each rule catches the fixtures it was authored against) - **not** an
> independent recall figure; the benchmark rows above are the broader measure (the holdout row is a
> separately sourced split, not a blind one). The benchmark is
> small and hand-built; a clean scan is **not** a security guarantee (see *Scope & honesty*).

## Engines
drain-scan runs its **own analysis over the solc compiler's AST** - **Slither is not used**.
- **drain-scan core** (`core/`): we invoke `solc` as a subprocess for the AST
  (`--combined-json ast`) and reason over it ourselves - a thin AST layer plus a light,
  name-level taint/reachability pass - for the semantic rules (allowance / permit /
  delegatecall / signature dataflow). No Slither, no SlithIR, no crytic-compile.
- **Semgrep** rules for the syntactic subset (a cross-check where the defect is visible in the
  shape of the code).

The two engines meet in one report; see [`docs/engine-split.md`](docs/engine-split.md) for
which rule lives where and why.

**Clean-room provenance (MIT, not AGPL).** The analysis core is written from scratch over the
solc AST and contains **no Slither code and no SlithIR**. An earlier v1 prototype of some rules
subclassed Slither detectors (e.g. `controlled-delegatecall`); every **shipped v2 rule was
re-derived from scratch** against the solc AST, using as reference only this project's own git
history, `RULES.md` and the labelled fixture anchors - **not** the Slither API or SlithIR. Slither
is AGPL-3.0 and drain-scan is MIT: Slither is neither a runtime dependency nor an install
requirement (importing it is forbidden in `core/`, `detectors/`, the driver and the scanner - see
[`core/__init__.py`](core/__init__.py) and [`requirements.txt`](requirements.txt)), and no Slither
source is vendored. `solc` is used only as an external subprocess to produce the AST.

## Layout
```
scan         the scanner entry point - `scan <path>` -> one unified report (venv+solc wrapper)
scanner/     scan.py: aggregates core + Semgrep hits, enriches them from rules.tsv
core/        the analysis engine: solc-AST compile, AST helpers, light taint, Detector base (no Slither)
rules.tsv    machine-readable rule registry (rule -> vector/severity/PoC/fix); scanner reads this
detectors/   drain-scan core detectors (one module per rule), written on core/
semgrep/     Semgrep rules (syntactic subset)
validate/    validation loop: run rules over the wal fixtures, assert vuln fires / safe silent, print P/R
docs/        scope, rule catalog, how-to-fix per rule
RULES.md     the rule catalog (what each rule flags, engine, severity, PoC anchor)
```

## Scan
Run the whole rule set over your code and get one report (vector / location / severity /
PoC-fixture / how-to-fix), regardless of which engine produced each hit:

```bash
scan path/to/Wallet.sol            # a single .sol file
scan path/to/project               # a Foundry/Hardhat project, or a plain folder of .sol
scan path/to/Wallet.sol --format json   # machine-readable (one record per finding)
scan path/to/Wallet.sol --no-fail        # don't exit non-zero on findings
```

Exit code is non-zero when anything is flagged, so `scan` doubles as a CI gate. Each finding
is joined to [`rules.tsv`](rules.tsv) - the single enrichment registry - so every rule reads
the same way. A clean scan is **not** a security guarantee (see *Scope & honesty*).

## Scope & honesty

**Scope.** drain-scan is a static linter for on-chain wallet/account *policy* - what the
contract code permits (approvals, delegate execution, upgrade authority, signature binding). It
covers **15 static wallet-drain patterns** (R1-R15; see [`RULES.md`](RULES.md)). It does **not**
cover dynamic/economic bugs (that is audit/fuzzing territory) or off-chain / UX-level attack
surface: fake-airdrop lures, address poisoning, blind-signing prompts and wallet-UI phishing are
out of scope by design, since they are not decidable from contract source.

**Compiler scope.** drain-scan analyzes Solidity **>=0.8** (solc's compact AST). A pre-0.8
source (solc 0.4-0.7, which emits a legacy AST the core does not read) is **refused with an
explicit compile error** - never silently reported as clean - so a false "safe" on an
unanalyzable wallet is impossible. To scan such code, pin a >=0.8 compiler/pragma.

**Taxonomy / overlap.** The rules are a coherent bundle, not mutually-exclusive detectors.
Several may flag one drain surface: R7 (delegatecall-hijack) and R8 (AA/7702 forward) share one
static primitive, R1 and R3 both map to approve-drainer, and R11 covers the plain-call /
`transferFrom` case that R7/R8 deliberately skip (a node is R11 *xor* R7/R8). Overlap is
intentional and the scanner de-duplicates per rule. We do **not** claim per-rule detection
novelty - the contribution is the coherent, PoC-backed, 0-FP-disciplined bundle plus the
reproducible *rule ⇄ fixture ⇄ benchmark* loop.

**0 false positives is a hard requirement** - a rule that fires on a genuinely-safe fixture
(incl. vendored OpenZeppelin / Solady / Uniswap Permit2) is not shipped. 0-FP is held above
recall: where a real incident cannot be caught without a false positive on canonical safe code,
the rule is documented as a non-fit rather than widened (see the R7-Parity and R11-Squid notes
in [`validate/anchors.holdout.tsv`](validate/anchors.holdout.tsv)).

**Small-sample honesty.** The benchmark is small and hand-built: **35 dev + 18 holdout labeled
fixtures** (53 dev + 22 holdout rule-anchor evaluations), with the holdout split held out from
the code the rules were written against. precision / recall = **1.0** means each rule fires on
its labeled vulnerable anchors and stays silent across the labeled real-safe corpus - it
demonstrates the method and the 0-FP discipline **on this corpus**. It is **not** a statistical
claim of generalization to wallets in the wild; treat it as a reproducible methodology artifact,
not a guarantee. A clean scan is not a security guarantee.

## License
MIT (see LICENSE).
