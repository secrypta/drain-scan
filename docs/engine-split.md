# Engine split - which rules are Semgrep (syntactic) vs the drain-scan core (semantic)

> **Architecture note (migration).** drain-scan's semantic engine is the **drain-scan core**:
> our own analysis over the **solc compiler AST** (`core/` - `solc --combined-json ast` via
> subprocess, a thin AST layer, and a light name-level taint/reachability pass). **Slither is
> not used** (no SlithIR, no crytic-compile). This replaced an earlier Slither-based prototype.
> Porting status: **complete - R1-R15 all run on the core** (`detectors/r1...r15`); no rule
> depends on Slither. The Semgrep rules (R2′/R6′/R10′) are unchanged by this migration and ship
> alongside the core as a syntactic cross-check. Read "the core" wherever an older note said
> "Slither".

drain-scan is built on two engines. This doc is the honest division of labour: which rules
Semgrep can express **cleanly at 0 false positives**, and which require the core's AST dataflow.
The rule of thumb:

> If the defect is visible in the **shape of the code** (a call form, a digest construction,
> an assignment with/without a guard in the same function), Semgrep expresses it.
> If deciding "defect vs safe" needs **dataflow** - is this value unbounded? is this address
> immutable/allowlisted? is a reset/pin present on the path? - it belongs to the **core**.

## Summary table

| id | flags | Semgrep? | authoritative engine | why |
|----|-------|----------|----------------------|-----|
| R1 | unbounded approve to arbitrary spender | partial (literal `type(uint256).max` only) | **core** | "arbitrary spender" = spender not immutable/allowlisted is a dataflow fact; amount-unbounded for a non-literal is too. A syntactic `approve(x, type(uint256).max)` catches only the literal case and still can't prove the spender is arbitrary -> FP-prone. |
| R2 | `setApprovalForAll(op,true)` to arbitrary operator | **yes (cross-check)** | core (+ Semgrep cross-check) | the call shape is syntactic; Semgrep drops literal-address operators. Proving `op` is not immutable/allowlisted is the core's. Shipped as a syntactic cross-check. |
| R3 | allowance left non-zero after action (no reset) | no | **core** | requires seeing an approve->use flow with no reset-to-0 afterwards - ordering/dataflow across statements. |
| R4 | permit/Permit2 consumed beyond action amount | no | **core** | requires comparing the signed/consumed amount to what the action needs - value dataflow. |
| R5 | auth signature w/o deadline/nonce/domain | no | **core** | requires proving a field is *absent* from the verified struct/path; syntactic "ecrecover present but no deadline" over-approximates massively -> FP. |
| R6 | `ecrecover` over raw/opaque (non-EIP-712) digest | **yes** | Semgrep (core optional) | the digest construction is syntactic: a plain `keccak256(abi.encode(...))` fed to `ecrecover` vs one built via `"\x19\x01"+DOMAIN_SEPARATOR`. Shipped. |
| R7 | delegatecall to mutable/attacker-settable target | no | **core** | "target is attacker-settable" is a dataflow fact - the core taints the delegatecall destination over the AST. |
| R8 | account exec to calldata target w/o allowlist | no | **core** | requires tracking a calldata-supplied target reaching a call with no allowlist check on the path. |
| R9 | standing trust/approval w/o codehash pin | **attempted, rejected** | **core** | see below. |
| R10′ | implementation/module swap w/o timelock | **yes** | Semgrep (+ core) | the swap is a syntactic assignment to an impl/module/delegate slot; "no timelock" = no `block.timestamp` delay guard in the function body. Shipped. The core additionally proves single-key + no guardian. |
| R11 | arbitrary caller-supplied call / unbound `transferFrom` spending a standing approval | no | **core** | an `address.call(data)` / `transferFrom` is static-indistinguishable from a legitimate allow-listed router; deciding "defect" needs the core to taint a caller-supplied target/amount reaching the spend with no allow-list. A syntactic match would FP on every canonical executor. |
| R12 | externally-callable unguarded initializer installs an authority role | no | **core** | requires proving the *absence* of a re-init guard / access-control modifier on an externally-reachable initializer that writes an authority slot - a whole-function property, not a call shape. |
| R13 | unvalidated approve over self-custodied (pooled) balance | no | **core** | needs two dataflow facts - the spender is caller-supplied/unvalidated, and the approved token is a balance the contract itself custodies - neither visible in the `approve` call shape. |
| R14 | reentrant callback re-targets a standing approval (CEI violation) | no | **core** | requires detecting a post-external-call re-read of externally-mutable storage then a transfer on that re-read state - ordering/dataflow across statements and an externally-reachable setter. |
| R15 | forged / permissive ERC-1271 contract-signer trust | no | **core** | requires proving the trusted signer is caller-supplied (not immutable/owner-configured) and that an asset sink is gated on its attestation - taint/dataflow, not a syntactic `isValidSignature` call. |

**Semgrep ships 3 rules cleanly:** R2 (cross-check), R6, R10′ - exactly the rules tagged
`core/semgrep` in `RULES.md`. The rest are **core-authoritative** (R2/R6 also have a core rule
as the authority). No Semgrep rule is shipped that produces a false positive on a safe
wallet-harness fixture; the validation loop (`validate/run_semgrep.sh`, and `validate/all.sh`)
enforces this.

## Benchmark wiring - one loop, two engines

The Semgrep rules are wired into the single dual-engine benchmark `validate/all.sh` (via
`validate/driver.py`), which dispatches each anchor by the `detector_module` extension:
**`.py` -> a drain-scan core detector**, **`.yaml` -> a Semgrep rule**. The Semgrep anchors live
in `validate/anchors.tsv` under rule ids **R2′ / R6′ / R10′** (primed), so each engine's variant
is reported as its own per-rule P/R line, separately from the core rule of the same vector
(R2, R6). A core (`.py`) rule not yet ported is reported as a pending SKIP, not a pass.

Semgrep DEV (unchanged by the core migration):

```
R2'   TP=1 FP=0 FN=0 TN=2 err=0  P=1.000 R=1.000 F1=1.000  [OK]
R6'   TP=1 FP=0 FN=0 TN=2 err=0  P=1.000 R=1.000 F1=1.000  [OK]
R10'  TP=1 FP=0 FN=0 TN=2 err=0  P=1.000 R=1.000 F1=1.000  [OK]
```

R6′ uses per-contract anchors (line-span filtered): it fires on
`BlindSignVector.sol::BlindSigWallet` and stays silent on the `TypedSigWallet` contract in the
same file.

## Cross-engine agreement (R2 / R6)

For the two vectors that have both a semantic rule and a Semgrep rule, the two engines are
validated on the **same anchors** and are expected to agree cell-for-cell - the
syntactic↔semantic cross-check that justifies shipping the Semgrep variant alongside the core.

> **Measurement note:** Slither has been removed; the semantic column is now the **core**. Both
> **R2 and R6 are ported to the core**, and on these shared anchors the core rule and its Semgrep
> variant agree cell-for-cell (verified via `validate/all.sh` DEV - every cell P=R=1.0). The
> Semgrep column is unchanged throughout.

| anchor | label | semantic (core) | Semgrep | agree |
|--------|-------|------------------------|---------|-------|
| `src/VulnerableWalletNFT.sol` | vuln | R2 fires (TP) | R2′ fires (TP) | ✓ |
| `src/SafeWalletNFT.sol` | safe | R2 silent (TN) | R2′ silent (TN) | ✓ |
| `set-approval-for-all/c-safe-impl/SafeOperatorFlow.sol` | safe | R2 silent (TN) | R2′ silent (TN) | ✓ |
| `src/BlindSignVector.sol::BlindSigWallet` | vuln | R6 fires (TP) | R6′ fires (TP) | ✓ |
| `src/BlindSignVector.sol::TypedSigWallet` | safe | R6 silent (TN) | R6′ silent (TN) | ✓ |

The engines *reach the same verdict by different means*: the semantic engine proves the operator
is not immutable/allowlisted (R2) and the digest's provenance by dataflow (R6); Semgrep matches
the call/digest *shape*. Agreement on every anchor is evidence the syntactic rule is a faithful
(if weaker) stand-in where no compile/dataflow is available.

## 0-FP probe - silence on the whole real-safe corpus

Beyond each rule's own safe anchors, every shipped rule is run over the **whole real-safe
corpus** (vendored OpenZeppelin, Solady, Uniswap Permit2, OZ TimelockController, plus every
vector's `c-safe-impl` tier - real code, not toy-safe). A rule that leaks shows up here as a
spurious finding on genuine safe code outside its own vector.

- **Core engine:** `validate/zero_fp_probe.sh` (see [`docs/zero-fp-probe.md`](zero-fp-probe.md))
  auto-discovers every ported core detector and sweeps the corpus; any finding is an FP candidate
  triaged to the detector owner (never path-suppressed). Current result: **all R1-R15 core
  detectors are silent on all 193 compiled safe files** (the Uniswap Permit2 files compile under
  their pinned solc 0.8.17, selected per-pragma) - **0 FP per rule**.
- **Semgrep rules:** every shipped Semgrep rule was run over
  all `c-safe-impl` fixtures - **0 findings, all cells**:

| rule | OZ ERC20/721/Permit/Asset | Solady ERC20/ERC1271 | Permit2 scoped | OZ Timelock/UUPS | other c-safe | total FP |
|------|---------------------------|----------------------|----------------|------------------|--------------|----------|
| R2′  | 0 | 0 | 0 | 0 | 0 | **0** |
| R6′  | 0 | 0 | 0 | 0 | 0 | **0** |
| R10′ | 0 | 0 | 0 | 0 | 0 | **0** |

The 0-FP claim is not just "silent on the matched safe anchor" but "silent on the whole
real-safe corpus". Reproduce: `WAL_ROOT=~/wal validate/all.sh` (wired anchors) and
`WAL_ROOT=~/wal validate/zero_fp_probe.sh` (broad core sweep).

## R9 - the honest negative result

R9 (persistent trust/approval to an external address with no codehash pin) was **attempted in
Semgrep and rejected** - it is not cleanly expressible, so it ships only as a **core** detector.

What a syntactic rule can see is the `approve(spender, amount)` call. What it cannot see is the
two facts that make R9 a *defect*:
1. the spender's **code is mutable** (CREATE2/metamorphic/upgradeable-delegate), and
2. **no codehash pin** exists on the trust/settle path (the pin may live in another function
   or another contract).

Both are dataflow/whole-contract properties. Concretely, two measurements against the
wallet-harness anchors:

- A bare `$T.approve($S, $A)` rule fires on the R9 vuln anchor (`Create2Vector.sol`
  `VulnerableApprover`, the `approve` at the trust site) **but also fires on genuinely-safe
  bounded-approve code** - e.g. `approve-drainer/c-safe-impl/SafeAllowanceFlow.sol:23`, a
  canonical OZ bounded approve. That is a **false positive on safe code**, which violates
  drain-scan's hard 0-FP requirement.
- Trying to subtract the safe cases with `pattern-not-inside` a function that references
  `.codehash` / `.codeId()` is unreliable under Semgrep's experimental Solidity support (it
  suppressed the true positive as well, i.e. it does not scope to the approve's own function
  cleanly), and in any case the pin commonly lives in a *different* function (`trust` pins,
  `settle` re-checks), which `pattern-not-inside` cannot reach.

The attempted rule (kept here for the record, **not shipped**):

```yaml
# R9 ATTEMPT - DO NOT SHIP: FPs on every bounded approve; cannot see mutable-code or
# a pin in another function. R9 is a core detector.
rules:
  - id: standing-approval-without-codehash-pin
    languages: [solidity]
    severity: WARNING
    message: standing approval without a codehash pin (see docs/engine-split.md)
    patterns:
      - pattern: $T.approve($SPENDER, $AMT)
      - pattern-not-inside: |
          function $F(...) { ... $X.codehash ... }
      - pattern-not-inside: |
          function $F(...) { ... $X.codeId() ... }
```

Conclusion: R9 belongs to the **core**, which can (a) establish that the approved address is
mutable-code and (b) check for a codehash pin on the approval/spend dataflow. (The core models
this as: a contract that *obtains* a code identity but never *enforces* it in a comparison -
see `detectors/` and `RULES.md#r9`.)

## Semgrep Solidity support - practical notes (for future work)

- Solidity is an **experimental** Semgrep language (tree-sitter). Call/assignment/sequence
  patterns match reliably (R2/R6/R10′ all validate at 0 FP).
- `metavariable-regex` works; **`metavariable-pattern` with `pattern-not` did not** filter a
  metavariable in testing - use `metavariable-regex` (e.g. a negative-lookahead to drop
  literal `0x...` address operands, as in R2).
- `pattern-not-inside: function ...{ ... }` does not reliably scope to the enclosing function
  under the experimental grammar - avoid relying on it for "absence within this function".
- Function-body sequence patterns (`$SLOT = $NEW;` with `...`, statement-to-statement) do
  work (R6 digest->ecrecover, R10′ slot-assign).
