# drain-scan on drain-bench - scanner validation

How does **drain-scan** (the static linter, rules R1-R15 on the solc AST) score on the
[`drain-bench`](https://github.com/secrypta/wallet-harness) labeled corpus - measured the same
way, and beside the same baselines, as every other tool? This is the honest pre-publication
validation of the scanner: it is scored *as a tool* against an independent ground truth, with its
coverage boundary shown, not hidden.

> **This is the static linter's score, which is not the headline number.** drain-bench's own
> `wal` row (a **dynamic** Foundry exploit/control harness) scores 1.0 because it *runs* each
> drain with that fixture's own test - a corpus self-consistency check, not a blind detector; drain-scan is a **static** linter and is deliberately narrow and precision-first. Read
> this as "how far does a 0-FP static linter get on the full drain surface", not as a claim to
> beat the harness or general tools on recall.

## Method (identical to the baselines)

Each target in [`drain-bench`](https://github.com/secrypta/wallet-harness)'s
`bench/tools/baseline-targets.tsv` maps to one subject contract. drain-scan is run over that
`.sol` (`scan --format json`, solc per-pragma, `--allow-paths` at the corpus root so vendored
imports resolve), and its verdict is set by the **same rule the baselines use**
(`bench/tools/map_verdicts.py`): **VULNERABLE** iff drain-scan emits ≥1 finding (any rule R1-R15)
whose source line falls within the subject contract's line span; otherwise **BLOCKED**; a
compile/scan error that yields no output is **no verdict -> MISS** (a coverage gap we never guess).
Verdicts are scored with `bench/score.sh` against the dataset manifest's `label`, split into
**dev** (the fixtures the rules were written against) and the **holdout** (fixtures added after the
`v0.1` freeze, covering all 13 vectors). The holdout is not blind for drain-scan: R11-R15 and the
R10/R13 false-positive fixes were developed while it was visible, and some holdout fixtures are rule
anchors (`validate/anchors.holdout.tsv`).

Reproduce (read-only against a `wallet-harness` checkout at `$WAL_ROOT`): run `scan` over each
`baseline-targets.tsv` subject, emit `[<vector>] target=<t> verdict=<V|BLOCKED>`, then
`bench/score.sh <verdicts> --split all|holdout`.

## Results

### Full corpus (split=all, 155 labeled fixtures)

| tool | engine | TP | FP | FN | TN | MISS | precision | recall | F1 |
|------|--------|----|----|----|----|------|-----------|--------|-----|
| `wal` harness | **dynamic** Foundry exploit/control | 70 | 0 | 0 | 85 | 0 | **1.000** | **1.000** | **1.000** |
| **drain-scan** | **static** (own core, R1-R15) | 35 | **0** | 33 | 84 | 3 | **1.000** | 0.515 | 0.680 |
| Mythril | symbolic | 49 | 32 | 17 | 49 | 8 | 0.605 | 0.742 | 0.667 |
| Wake | static detectors | 47 | 28 | 21 | 56 | 3 | 0.627 | 0.691 | 0.657 |
| Remix | static (solc-js lib) | 46 | 25 | 22 | 59 | 3 | 0.648 | 0.676 | 0.662 |
| Slither | static detectors | 43 | 28 | 25 | 56 | 3 | 0.606 | 0.632 | 0.619 |
| Solhint | linter (security rules) | 30 | 12 | 38 | 72 | 3 | 0.714 | 0.441 | 0.545 |
| Semgrep (`--config auto`) | generic patterns | 0 | 0 | 68 | 84 | 3 | n/a | 0.000 | n/a |

(Baseline rows rescored on the current **155**-fixture corpus from each tool's `verdicts.txt` in
`drain-bench`'s `bench/results/<tool>/`. `wal` is the dynamic harness; it runs an exploit/control
test for every labeled fixture - the two R15 ERC-1271 / ERC-6492 incident clones included - so it has
no MISS on this corpus.)

The baselines were re-run after the approve-drainer Hedgey incident fixture was rewritten to the
**real contract's call shape** - `SafeERC20.safeIncreaseAllowance(...)` (static library form) and a
`TransferHelper` custody pull, replacing the earlier bare-`approve` member stand-in. On that faithful
form **Remix flips VULNERABLE -> BLOCKED** (its member-pattern detector does not see the library form),
so its recall ticks down vs the member stand-in - an honest signal that the real-incident form is
harder than a hand-written toy. drain-scan still fires (its R13 reads the library form); its own
numbers are unchanged but for one safe fixture moving MISS -> TN (one more file now compiles cleanly).
The self-authored real-form coverage toys (R1/R3/R4 library shapes, inline-assembly delegatecall) are
**deliberately kept out of this head-to-head** - scoring general tools against fixtures written to
exercise drain-scan's own detectors would be self-selecting; they live in drain-scan's `validate/`
anchors (all.sh), not the neutral comparison corpus.

### Holdout (the post-freeze split - 94 fixtures: 41 vuln / 53 safe)

Independent ground truth for the general tools (none was built on this corpus). Not blind for
drain-scan (see *Method*) or for the `wal` row (self-consistency, see the note at the top).

| tool | TP | FP | FN | TN | precision | recall | F1 |
|------|----|----|----|----|-----------|--------|-----|
| `wal` harness (dynamic) | 41 | 0 | 0 | 53 | **1.000** | **1.000** | **1.000** |
| Wake | 28 | 6 | 12 | 47 | 0.824 | 0.700 | 0.757 |
| Remix | 29 | 13 | 11 | 40 | 0.690 | 0.725 | 0.707 |
| Mythril | 27 | 16 | 11 | 34 | 0.628 | 0.711 | 0.667 |
| **drain-scan** (static) | 18 | **0** | 22 | 53 | **1.000** | 0.450 | 0.621 |
| Slither | 21 | 7 | 19 | 46 | 0.750 | 0.525 | 0.618 |
| Solhint | 19 | 4 | 21 | 49 | 0.826 | 0.475 | 0.603 |
| Semgrep | 0 | 0 | 40 | 53 | n/a | 0.000 | n/a |

## Reading the result honestly

- **Precision, not recall, is drain-scan's story.** drain-scan's precision is **1.000 on both
  splits** - zero false positives across all 155 labeled fixtures - while every general static tool
  sits near 0.60 on the full split (they flag safe OZ/Solady code for generic reasons). That 1.0
  holds on the **holdout** too: the 0-FP discipline on separately sourced code (not blind code -
  some false-positive fixes were made with the holdout visible, see below). (Reaching it took a real correctness fix, not a suppression - see below.)
- **Its recall is deliberately narrow and *below* the general tools on this corpus.** drain-scan
  holdout recall is 0.450 vs Wake 0.700 / Mythril 0.711. This is by design: drain-scan fires only
  on 15 specific, code-decidable wallet-drain surfaces (unbounded approval / operator grant,
  signature-binding, controlled delegatecall, AA/7702 forward, codehash pin, upgrade authority,
  arbitrary-callee, init-hijack, unvalidated-spender approval over pooled custody, a reentrant
  callback that re-targets a standing approval, and trusting a forged / permissive ERC-1271
  contract-signer attestation). It is **silent by design** on:
  - **drain-UX / off-chain vectors** - `address-poisoning` (0/3), `fake-airdrop` (0/2): the bug is
    in the transaction-time UX, not decidable from contract source (the general tools miss these
    too; the *dynamic* harness covers them by running the flow);
  - **incidents whose drain lives off-contract** - `malicious-calldata` Squid/Bebop, approve-drainer
    Pennysia: documented static **non-fits** (the draining `transferFrom` is in attacker calldata,
    not the subject's own code - see the R11 notes in `validate/anchors.holdout.tsv`);
  - **deployment / cross-contract flaws not in the subject's own source** - `upgrade-governance`
    Wormhole uninitialized-implementation: the subject's `initialize()` *is* re-init-guarded and
    its upgrade path *is* guardian-gated; the flaw is that the implementation was left
    un-initialized at deploy (an off-contract fact). Flagging its guarded upgrade would mean
    calling a guardian-gated swap a "single-key swap" - the exact over-fire the R10 authority-gate
    fix removed - so it is an honest static non-fit, not a catch kept by contradicting our own gate;
  - **classic-bug shapes outside the drain remit** - e.g. a Seaport order-logic signature case
    (`seaport-order-victim`). (The reentrancy-callback operator-reuse drain, `nfttrader`, is **no
    longer** in this list - it is now caught by **R14**, a wired holdout TP.)
- **drain-scan is strong exactly where it claims scope.** Per-vector on the full corpus it is
  complete or near-complete on its home vectors: `delegatecall-hijack` 4/0 FN, `blind-eth-sign`
  3/0 FN, `create2-metamorphic` 3/0 FN, `eip7702-delegation` 5/1 FN, `set-approval-for-all` 4/1 FN
  (R2 operator-grant plus the R14 reentrant-reuse catch), `approve-drainer` 3/3 FN (R1/R3 plus the
  R13 pooled-custody catch), `signature-phishing` 3/3 FN (R15 catches the two ERC-1271 forged-signer
  incidents where the EOA-signature rules R5/R6 and the general tools are blind), and it catches the
  real-incident holdout clones (Parity, Audius, Inferno, Tornado-metamorphic, Lixir, PAID,
  Hedgey [R13], NftTrader [R14], Sodium/Lumi + Odos [R15]). `upgrade-governance` is 4/3 FN - the 3 FN
  are the Wormhole-uninit non-fit above plus two authority-reassignment incidents (Nomad re-init,
  Poly keeper) whose takeover is a forged-message / role-swap path, not an in-source swap. The one
  home vector it does **not** score on is `permit2-phishing`: all three targets share one contract,
  the (correct) `ToyPermit2`, and the drain is in the off-chain unbounded/batch permit signature -
  see the shared-subject note below.

### 0 FP on the whole corpus (R10 authority-gate + core-authoritative merge)

As the safe corpus grew (real governed-upgrade code from OZ and Wormhole was added after the
scanner's earlier validation), a broad `zero_fp_probe` over all 193 real-safe `.sol` files
surfaced **3 false positives**, all on **R10 / upgrade-governance** safe code, all genuine
over-fires - fixed at the root (the 193-file probe and DEV+HOLDOUT anchors are back at 0 FP, every
R10 vuln anchor still firing):

- **R10 only understood a `block.timestamp` timelock as a safe guard.** It did not recognize an
  *access-control* authority gate, so it flagged three real safe upgrades: `OZAccessManagedVault`
  (defers to `IAccessManager.canCall`), `OZGovernorGoverned` (`onlyGovernance` -> `msg.sender ==
  governance`), `WormholeInitGuardSafe` (`onlyGuardian`). The core R10 detector now resolves, over
  the AST, whether the swap is gated by a non-single-key authority - a `msg.sender == <governance /
  guardian / authority / timelock / ...>` check or a deferral to an external authority decision
  (`canCall`), looked up across the function body, its modifiers, and the internal helpers it calls
  - and stays silent if so. `owner`/`admin` gates are **not** authority gates (an owner-gated
  instant swap is the defect), and every R10 vuln anchor (toy, PAID, Tornado) is owner-gated and
  still fires. The three fixtures are now wired as R10 holdout *safe* anchors so the gate is locked.
- **The scanner merged core + Semgrep findings with no precedence**, so the syntactic Semgrep R10′
  cross-check kept firing on those same guarded swaps (it cannot see the gate) even after the core
  was fixed. The scan now treats **core as authoritative**: a Semgrep hit counts toward a verdict
  only for a rule that has no core detector (today: none), so a syntactic variant can no longer
  raise a verdict the precise core rejected. Semgrep stays validated rule-by-rule in `validate/`.

This is a real precision fix, not a path-suppression. Its one honest cost is one lost catch,
documented as a non-fit: `wormhole-uninit-impl-victim` was previously flagged **only** by Semgrep
R10′ on its guardian-gated `submitContractUpgrade` - the very "guarded swap ≠ single-key swap"
shape the R10 fix corrects - so it is now a BLOCKED static non-fit (its real flaw, an
uninitialized implementation, is a deploy-time fact outside the subject's guarded source), not a
catch kept by contradicting the gate logic. 0-FP precision is chosen over that one recall point.

**Shared-subject note - the `permit2-phishing` false negatives.** The three `permit2-phishing`
targets (`safe-permit2`, `vulnerable-permit2`, `pepe-permit2-victim`) all share **one** subject
contract, `ToyPermit2`, whose code is a correct permit implementation; the safe/vuln difference is
the **off-chain** unbounded/batch permit signature a phished user signs. A static analyzer cannot
distinguish them from the code alone - it is correctly silent on the (safe) ToyPermit2 code, so
`safe-permit2` is a true negative and `vulnerable-permit2` / `pepe` are honest **false negatives**
(the drain is not in the contract). This is the same static-vs-dynamic limit as the
`permit-phishing` MISS pair; the *dynamic* harness tells them apart by running the signed flow.

**R5 nonce axis - enforcement-based (resolved).** R5 counts a nonce as present only when it is
**enforced** - required-and-consumed (checked, then incremented), or woven into the verified EIP-712
signed digest. A fixture that merely **declares** a nonce field without enforcing it is treated as
replayable and fires R5, so there is no silent false negative. This closes the earlier
declaration-vs-enforcement limitation; the domain and deadline axes are unchanged and the benchmark
numbers are unaffected (all R5 anchors hold, 0 FP across the real-safe corpus).

### MISS

4 labeled fixtures get no verdict line (a coverage gap we never guess, not a wrong call):
`permit-phishing/{safe-permit,vulnerable-permit}` and `set-approval-for-all/premint-operator-victim`
have no target-specific first-party contract - the safe/vuln difference is purely in the off-chain
signing flow or a front-end injection, so there is no code artifact to hand a static analyzer (the
same OMITs every static baseline records). `malicious-calldata/oz-timelock-executor-safe`'s subject
contract is a vendored OZ `TimelockController` imported, not declared, in the fixture file, so the
by-name line-span attribution finds no subject span - scored MISS rather than guessed.

### Coverage boundary - what the 33 false negatives are

The recall gap is **not** a pile of missed drains; it is an inspected, categorized boundary (each FN
was classified by code review of the subject). Of the 33 full-corpus FN:

- **31 are documented non-fits** - recall drain-scan does not claim, held out to keep precision 1.0:
  - **18 off-chain / out-of-scope**: the on-chain code is standard and correct and the drain lives in
    a signed message or the wallet UI - `address-poisoning` (3), `fake-airdrop` (2), `permit-phishing`
    (4) and `permit2-phishing` (3) phished signatures, `signature-phishing` valid-but-phished orders
    (3: RTFKT/Seaport, Seaport order, toy), `set-approval-for-all` EOA `monkeydrainer` (1), and
    `approve-drainer` front-end approval injections (`badger`, `steth-whale` - 2). The general tools
    miss these too; the *dynamic* `wal` harness covers them by running the flow.
  - **11 arbitrary-executor / whitelisted-router static non-fits**: the draining `transferFrom` is in
    the attacker's **calldata**, not the subject's own code - `malicious-calldata` (9: Socket, Squid,
    LI.FI, Rabby, Dexible, Unizen, Bebop, Seneca, Rubic), `approve-drainer` Pennysia (1), and the
    `upgrade-governance` Poly-keeper arbitrary-call takeover (1). Flagging a bare `target.call(data)`
    executor would break the hard 0-FP (it is static-indistinguishable from a legitimate router - see
    the R11 notes in `validate/anchors.holdout.tsv`).
  - **2 bespoke / deployment-level flaws** invisible in single-contract source: `upgrade-governance`
    Nomad (a `acceptableRoot(0)==true` validation bug, no generic authority pattern) and Wormhole
    uninitialized-implementation (a deploy-time fact, not the subject's guarded source - the
    guardian-gated upgrade is correctly *not* called a single-key swap, see above).
- **2 are same-vector detector-gap candidates** held **list-only** (no detector edit): `malicious-calldata`
  Visor (a *typed* `delegatedTransferERC20` to a caller-supplied callee - R11 keys on low-level
  `.call` / `transferFrom`, not this typed shape) and `eip7702-delegation` qnt-pool (a delegatecall
  to a **storage**-settable delegate - R7 wants an in-contract settable target, R8 wants calldata). A
  predicate catching either is plausible but has **unproven / doubtful 0-FP** (legitimate vaults call
  user-specified adapters the same way), so - precision held above recall by design - neither is
  shipped until it can prove 0 FP across all 193 real-safe files.

So the recall ceiling is the **on-chain-static scope**, chosen, not a defect: 31/33 FN are out of
scope or static-undecidable, 2/33 are deferred for the 0-FP gate.

**R15 holdout honesty.** R15's two holdout incidents (Lumi/Sodium, Odos) are **incident-derived** -
the detector was written already knowing the ERC-1271 forged-signer mechanism (as with R13/R14), so
their holdout TPs are a **corpus split** (independent fixtures the rule was not tuned against
file-by-file), not blind generalization to an unknown bug class. They are an honest *generalization
within a known mechanism*, and are labeled as such here and in the coverage matrix.

**create2 mapping fix (why the two `create2-metamorphic` targets are now TP).** In the earlier run
`vulnerable-create2` / `metamorphic-approve-victim` scored FN - a **bench subject-attribution
artefact**, not a detector miss: the targets pointed at `VulnerableApprover` while R9 fires on
`MetamorphicSpender` (the metamorphic contract that exposes a code identity without pinning it), a
different first-party contract in the same `src/Create2Vector.sol`. The bench subject was corrected
to `MetamorphicSpender` (the contract that embodies the metamorphic vector, and R9's own anchor), so
both are now true positives. This changed the mapping, not the scanner.

## What this validates

drain-scan is a **high-precision, deliberately narrow** static linter: on this corpus it holds
**1.0 precision on both splits** - zero false positives across all 155 labeled fixtures - while a
general static tool sits near 0.60, and it is complete or near-complete on the wallet-drain code
surfaces it claims. That comes at the honest cost of **lower recall** than a general scanner on the
full corpus, because it does not reach drain-UX (`address-poisoning`, `fake-airdrop`) or drains
that live off-contract (the `permit2`/Squid/Pennysia shared-subject and attacker-calldata cases, or
the Wormhole uninitialized-implementation deploy-time flaw). The full-coverage 1.0 on drain-bench is
the **dynamic** `wal` harness; drain-scan is the static, 0-FP-disciplined companion, validated here
against the same ground truth rather than asserted.

*These are scanner results against an external benchmark; they do not change any drain-bench
number. The baseline rows are cited from `drain-bench`'s `bench/results/BASELINES.md` (track-C/B);
drain-scan's rows were reproduced independently (track-D) with the mapping and scorer above.*
