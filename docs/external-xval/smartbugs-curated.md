# External cross-validation - SmartBugs-Curated (`access_control`), scanner side

This is the **drain-scan (scanner) side** of the SmartBugs-Curated cross-validation. The labelled
corpus, its line-level ground truth, the per-file license review and the ported `.sol` fixtures
live in the `wallet-harness` repo under
[`bench/external/smartbugs-curated/`](https://github.com/secrypta/wallet-harness) (its
`README.md` + `ground-truth.tsv` are the source of truth for provenance and expectations). This
note records what the drain-scan **rules** do when run over that independent corpus, so a reviewer
can see where our view agrees with an outside taxonomy - and, just as honestly, where our scope
ends.

It changes **no** benchmark number: like `bench/external/swc-xval/`, SmartBugs-Curated is kept out
of the drain-bench dataset/manifest and the `fixtures/**` corpus. These are scanner results only.

## Setup

- Upstream: `smartbugs/smartbugs-curated` @ `230e649123477eff332742a59a1c7cc6dc286cab`
  (retrieved 2026-11-14), `access_control` category. Repo code Apache-2.0; each contract keeps its
  **original** upstream license. A per-file license review was done before vendoring any `.sol`;
  GPL-3.0 (`parity_wallet_bug_1`) is **referenced by URL only, never copied**.
- Imported examples are **ported `^0.4.x` -> `^0.8.17`** to compile under our pinned solc, so they
  are not byte-identical to upstream (each port diff is in the file header). Value = **taxonomy
  agreement**, not incident reproduction.
- Scanner: drain-scan **core** engine (own solc-AST analysis, no Slither), rules R1-R12
  (`scan-d`). Command, per file: `SOLC_VERSION=0.8.17 scan <file>`.
- **Point-in-time snapshot.** This report records the run as executed on 2026-11-14 with the
  then-current ruleset (R1-R12) and real-safe probe corpus (140 files). It was **not** re-executed
  for the later R13-R15 (pooled-custody approve / reentrant approval-reuse / ERC-1271 contract-signer),
  which target wallet-specific drain surfaces, nor for the expanded 193-file safe corpus; the figures
  below are therefore the as-run numbers, not the current corpus totals.

## Honest framing: a narrow tool on a general corpus

drain-scan is a **narrow wallet-drain linter** (approval / signature / delegatecall / upgrade /
init-hijack drains). SmartBugs `access_control` is a **general** access-control category. drain-scan
is **not a leader on it and does not claim to be**: it is in scope for exactly two sub-families -
**delegatecall** (R7/R8) and **unprotected-authority / init-hijack** (R12, incl. the
wrong-constructor-name variant, where a misnamed "constructor" stays publicly callable and seizes an
authority role) - and is silent by design on the rest (`tx.origin` auth, unprotected
`selfdestruct`, refund/comparison logic bugs, arbitrary storage writes). The value is (1)
cross-validation on the overlapping sub-families and (2) an honest demonstration of the scope
boundary: silence on an out-of-scope bug is a precision property, not a false negative.

## Result - full `access_control` set

Ground truth lines are the **upstream (0.4) annotations**; drain-scan flags land on the **ported**
lines (the file headers carry the port diff). Scanner = `scan-d` (R12), solc 0.8.17.

### In scope - flagged (agreement with GT)

| file | GT (orig. lines) | sub-family | drain-scan verdict |
|------|------------------|------------|--------------------|
| `FibonacciBalance_0.8.sol` | 31, 38 | delegatecall | **R7 + R8** at both delegatecall sites (`withdraw`, `fallback`) ✅ |
| `../swc-xval/SWC-112-proxy-vulnerable.sol` | 19 | delegatecall | **R7 + R8** ✅ (see `swc-xval`) |
| `incorrect_constructor_name1_0.8.sol` | 20 | init-hijack | **R12** @ `Missing.IamMissing` ✅ |
| `incorrect_constructor_name2_0.8.sol` | 18 | init-hijack | **R12** @ `Missing.missing` ✅ |
| `incorrect_constructor_name3_0.8.sol` | 17 | init-hijack | **R12** @ `Missing.Constructor` ✅ |
| `multiowned_vulnerable_0.8.sol` | 38 | init-hijack | **R12** @ `MultiOwnable.newOwner` ✅ |
| `unprotected0_0.8.sol` | 25 | init-hijack | **R12** @ `Unprotected.changeOwner` ✅ |
| `rubixi_0.8.sol` | 23, 24 | init-hijack | **R12** @ `Rubixi.DynamicPyramid` ✅ |
| `wallet_03_wrong_constructor_0.8.sol` | 19, 20 | init-hijack | **R12** @ `Wallet.initWallet` ✅ |

### Out of scope - silent by design (0 FP)

| file | GT (orig. lines) | upstream defect | drain-scan verdict |
|------|------------------|-----------------|--------------------|
| `phishable_0.8.sol` | 20 | `tx.origin` auth | **CLEAN** - out of scope ◻️ |
| `simple_suicide_0.8.sol` | 12, 13 | unprotected `selfdestruct` | **CLEAN** - no authority-role install ◻️ |
| `wallet_02_refund_nosub_0.8.sol` | 36 | refund state-update logic | **CLEAN** - out of scope ◻️ |
| `wallet_04_confused_sign_0.8.sol` | 30 | comparison logic bug | **CLEAN** - out of scope ◻️ |

### Referenced only (not vendored / not portable)

- `parity_wallet_bug_1.sol` - GPL-3.0, referenced by URL + commit only (copyleft, never copied).
- `parity_wallet_bug_2.sol` - the ~200-LOC WalletLibrary; an impractical faithful port. Same R12
  class; the Parity incident is validated independently as an R12 **holdout** anchor.
- `mycontract.sol` - upstream license unverified; referenced only.
- `arbitrary_location_write_simple.sol`, `mapping_write.sol` - SWC-124 arbitrary storage write via
  a `0.4`-only `array.length` write; the defect cannot survive a `>=0.5` port, so not run (and
  out of scope regardless).

## Score

- **In-scope sub-family: 9 / 9 match** (delegatecall ×2: `FibonacciBalance`, `proxy`; init-hijack
  R12 ×7: `incorrect_constructor_name1/2/3`, `multiowned_vulnerable`, `unprotected0`, `rubixi`,
  `wallet_03_wrong_constructor`). **0 false negatives in scope.**
- **Out-of-scope: 4 / 4 silent** (`phishable`, `simple_suicide`, `wallet_02_refund_nosub`,
  `wallet_04_confused_sign`). **0 false positives.**

Verified per-flag: each R12 hit lands on the exact GT-annotated authority-installing function
(e.g. `rubixi.DynamicPyramid` sets `creator = msg.sender` while `onlyowner` gates on
`msg.sender == creator`; `wallet_03.initWallet` sets `creator` gated by `migrateTo`'s
`creator == msg.sender`). R12 fires only on an externally-reachable function that seizes an
**authority gate** with no modifier / one-shot guard / `_disableInitializers`; a *protected*
setter (`onlyOwner`, OZ `Ownable`) is suppressed - the full `zero_fp_probe.sh` (140 real-safe
files) stays 0 FP with R12 included, so the four out-of-scope positives above are the external,
independent confirmation of that discipline.

### Note - the R12 wrong-constructor-name sub-family

Five of the seven R12 matches (`incorrect_constructor_name1/2/3`, `rubixi`, `wallet_03`) are
upstream-categorized as "wrong constructor name". After a `>=0.5` port the wrong-name footgun
itself vanishes; what remains - and what R12 flags - is the **residual, still-real** defect: a
publicly-callable function that installs the privileged party (`owner`/`creator`) with no guard.
This is exactly R12's class (name-independent), not a coincidental match. It is reported here as a
sub-family drain-scan covers, **not** a claim over the whole `access_control` category.

These are scanner (drain-scan) results; they do **not** affect the wallet-harness benchmark numbers.
