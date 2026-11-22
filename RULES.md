# drain-scan rule catalog

Each rule flags a drain surface in wallet/account code, maps to a vector in the
`wallet-harness` corpus, and is anchored to a vulnerable PoC fixture (must fire) and a safe
fixture (must stay silent - 0 FP). Engine: the drain-scan **`core`** (our own analysis over the
solc AST - **Slither is not used**) or **`semgrep`** (syntactic).

> Engine status: the analysis **core** (own solc-AST analysis) has fully replaced Slither -
> **Slither is not used anywhere**. Every rule in this catalog runs on the core (`detectors/rN_*.py`).
> Three rules additionally ship a syntactic **Semgrep** cross-check variant (R2′/R6′/R10′), which
> `validate/all.sh` reports as separate per-rule lines (engine agreement check). `rules.tsv` is
> the machine registry; this file is the human catalog.
>
> **Clean-room / licensing:** the core contains **no Slither code and no SlithIR**. A v1 prototype
> of some rules subclassed Slither detectors; every shipped v2 rule was **re-derived from scratch**
> on the solc AST, referencing only this repo's git history, this catalog and the fixture anchors -
> not the Slither API/SlithIR. Slither is AGPL-3.0; drain-scan is MIT. Slither is not a dependency,
> its import is forbidden in `core/`/`detectors/`/driver/scanner (see `core/__init__.py`), and no
> Slither source is vendored.

| id | flags | vector (wal) | engine | severity |
|----|-------|--------------|--------|----------|
| R1 | unbounded approve (`type(uint256).max` / unbounded) to a non-allowlisted spender | approve-drainer | core | high |
| R2 | `setApprovalForAll(op,true)` to a non-constant/arbitrary operator | set-approval-for-all | core (+semgrep R2′) | high |
| R3 | allowance left non-zero after the action (no reset) | approve-drainer | core | medium |
| R4 | permit/Permit2 consumed beyond the action amount | permit-phishing / permit2-phishing | core | high |
| R5 | auth signature verified without deadline / nonce / domain binding (replayable) | signature-phishing | core | high |
| R6 | `ecrecover` over a raw/opaque digest not built via EIP-712 domain (ERC-1271) | blind-eth-sign | core (+semgrep R6′) | high |
| R7 | delegatecall to a mutable / attacker-settable target (governed proxy suppressed) | delegatecall-hijack | core | high |
| R8 | account forwards execution to a calldata-supplied target with no allowlist (AA / EIP-7702) | eip7702-delegation / malicious-calldata | core | high |
| R9 | persistent trust/approval to an external address with no codehash pin | create2-metamorphic | core | medium |
| R10 | implementation/module/delegate swappable by a single key with no timelock/guardian | upgrade-governance | core (+semgrep R10′) | high |
| R11 | a contract that spends a standing approval does so via an arbitrary caller-supplied call (F1, custody-gated) or an unbound, un-authorized `transferFrom` (F2) | malicious-calldata / approve-drainer | core | high |
| R12 | an externally-callable function installs an authority role (a state var the contract uses to gate `msg.sender`) with no re-init guard, modifier, or access control - anyone can seize it (init-hijack; name-independent) | init-hijack (overlaps delegatecall-hijack / upgrade-governance) | core | high |
| R13 | `approve`/`forceApprove`/`increaseAllowance` to a **caller-supplied, unvalidated** spender over a token balance the contract itself custodies (pooled custody) - the residual allowance drains the pool | approve-drainer | core | high |
| R14 | a contract honours a standing `setApprovalForAll` / approval *after* an external call whose callback re-enters an unguarded entry point and re-reads externally-mutable storage (check-effects-interactions violation) - the victim is swapped mid-callback and drained | set-approval-for-all (reentrancy) | core | high |
| R15 | a wallet authorizes an asset sink (transfer / approve / arbitrary call) on an ERC-1271 `isValidSignature` attestation from a signer **contract it does not control** - a caller-supplied / mutable signer (i), a permissive result not strictly equal to the `0x1626ba7e` magic (ii), or an ERC-6492 counterfactual deploy-and-trust (iii) - so an attacker forges a "valid" signature | signature-phishing | core | high |

## Severity & rating

Each rule carries a **severity** (the `severity` column of this catalog and of
[`rules.tsv`](rules.tsv), which the `scan` CLI reads). Two tiers, graded by how directly the
flagged *code* leads to loss of assets or loss of account control:

- **high** - the flagged condition is itself a direct full-asset-drain or account-takeover
  primitive: a standing unbounded approval / operator grant to a non-fixed spender (R1, R2); an
  approval to an unvalidated caller-supplied spender over a contract-custodied pool (R13); an
  over-broad, replayable, or forgeable signature authorization (R4, R5, R6); attacker-settable
  delegate or arbitrary execution in the account's own context (R7, R8, R11); a single-key
  implementation/pointer swap (R10); an authority role seizable by one unguarded call (R12); or a
  re-entrant callback that re-targets a standing operator grant / approval mid-execution (R14).
- **medium** - an enabling or residual-hygiene weakness that widens the drain surface but needs a
  further precondition to realize the loss: a lingering non-reset allowance after the action (R3),
  or trust in an external address with no codehash pin, exploitable only if that code is swapped
  (R9).

| severity | rules |
|----------|-------|
| high     | R1, R2, R4, R5, R6, R7, R8, R10, R11, R12, R13, R14, R15 |
| medium   | R3, R9 |

**Contract rating.** A scan's overall rating for a contract is the **maximum severity among the
rules that fired** (high > medium), or **CLEAN** when no rule fired. This is a **drain-risk**
signal over the wallet/account *policy* drain-scan models - *not* a general security audit: a
CLEAN rating means none of drain-scan's drain patterns matched, **not** that the contract is safe (see
*Scope & honesty* in the README). Severities are drain-impact grades, not CVSS scores.

## Standard taxonomy mapping

Where drain-scan's rules line up with public vulnerability taxonomies. IDs were verified against
the primary sources (SWC Registry `swcregistry.io`, MITRE CWE `cwe.mitre.org`); each SWC->CWE link
is the one the SWC entry itself declares. A **direct SWC exists only for R5/R6/R7/R14** - the other
eleven are honestly marked *no direct SWC* with the closest CWE rather than force-fit to a loose
SWC id.

| id | SWC | DASP Top-10 | CWE (primary) | also |
|----|-----|-------------|---------------|------|
| R1  | - (no direct SWC) | Access Control | CWE-284 Improper Access Control | CWE-269 |
| R2  | - (no direct SWC) | Access Control | CWE-284 Improper Access Control | CWE-862 |
| R3  | - (no direct SWC) | Access Control | CWE-459 Incomplete Cleanup | - |
| R4  | - (no direct SWC) | Access Control | CWE-863 Incorrect Authorization | CWE-284 |
| R5  | **SWC-121** Missing Protection against Signature Replay Attacks | Access Control | CWE-347 Improper Verification of Cryptographic Signature | CWE-294 |
| R6  | **SWC-122** Lack of Proper Signature Verification | Access Control | CWE-345 Insufficient Verification of Data Authenticity | CWE-347 |
| R7  | **SWC-112** Delegatecall to Untrusted Callee | Access Control | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | - |
| R8  | - (no direct SWC) | Access Control | CWE-829 Inclusion of Functionality from Untrusted Control Sphere | CWE-470 |
| R9  | - (no direct SWC) | - (closest: Unknown Unknowns) | CWE-345 Insufficient Verification of Data Authenticity | - |
| R10 | - (no direct SWC) | Access Control | CWE-284 Improper Access Control | CWE-269 |
| R11 | - (no direct SWC) | Access Control | F1 CWE-829; F2 CWE-863 Incorrect Authorization | CWE-284 |
| R12 | - (no direct SWC) | Access Control | CWE-665 Improper Initialization | CWE-284 Improper Access Control |
| R13 | - (no direct SWC) | Access Control | CWE-863 Incorrect Authorization | CWE-284 Improper Access Control |
| R14 | **SWC-107** Reentrancy | Reentrancy | CWE-841 Improper Enforcement of Behavioral Workflow | CWE-696 Incorrect Behavior Order (CEI) |
| R15 | - (no direct SWC) | Access Control | CWE-290 Authentication Bypass by Spoofing | CWE-347 Improper Verification of Cryptographic Signature |

Notes:
- **R6 maps to SWC-122, not SWC-117.** SWC-117 is signature *malleability* - a different defect
  R6 does not check. R6 flags `ecrecover` over a raw/opaque digest not bound via EIP-712 /
  ERC-1271, i.e. a *verification* gap (SWC-122 -> CWE-345).
- **R8 has no direct SWC**: SWC-112 covers `delegatecall` only, while R8 is a plain `CALL` /
  AA-EIP-7702 forward - the same untrusted-control-sphere weakness (CWE-829) with no SWC entry.
- **R9 has no direct SWC**: the metamorphic *attacker* side sits near SWC-106 (Unprotected
  SELFDESTRUCT), but R9 checks the *victim* side - a missing codehash pin - which no SWC names;
  closest is CWE-345.
- **R12 has no direct SWC**: SWC-118 (Incorrect Constructor Name) is the nearest historical entry
  but concerns the pre-0.4.22 named-constructor footgun, not a re-callable authority initializer.
  R12 is an *improper initialization* of a privileged role (CWE-665) left reachable without access
  control (CWE-284); no SWC id covers it.
- **R13 has no direct SWC**: granting an allowance to a spender the contract never validated is an
  *authorization* defect - the contract lets an arbitrary caller-supplied address pull against a
  pool it custodies - so the closest primary CWE is CWE-863 (Incorrect Authorization), with CWE-284
  (Improper Access Control) as the broader also. The approve-family drain surface (R1/R3/R13) has no
  SWC entry; R13 is marked *no direct SWC* like R1/R3 rather than force-fit.
- **R14 maps to SWC-107 (Reentrancy) -> CWE-841.** R14 flags a check-effects-interactions
  violation: the contract makes an external call (e.g. an ERC-721 `onERC721Received` callback) and
  *then* re-reads externally-mutable storage to key a `transferFrom` / standing-approval pull, so a
  re-entrant call into an unguarded entry point re-targets the victim mid-callback. SWC-107 is the
  direct match (DASP-1, Reentrancy); the CWE the SWC entry declares is CWE-841 (Improper
  Enforcement of Behavioral Workflow), and the ordering root cause is CWE-696 (Incorrect Behavior
  Order - effects applied after the interaction).
- **R15 has no direct SWC**: the SWC Registry predates EIP-1271 contract signatures and names no
  entry for trusting a signer *contract*'s attestation. R15 is an authentication bypass - an
  attacker forges a "valid" ERC-1271 answer from a signer they control - so the closest primary CWE
  is CWE-290 (Authentication Bypass by Spoofing), with CWE-347 (Improper Verification of
  Cryptographic Signature) as the also. It is deliberately **not** force-fit to SWC-122 (R6's entry,
  which is about `ecrecover`-shaped verification of an EOA signature); R15's defect is who the
  signer contract is and whether its answer is read strictly, not a raw-digest or replay gap.
- SWC Registry is archived upstream but remains the common shorthand; CWE is the durable
  cross-reference. This mapping is descriptive - not a severity or a coverage claim.

## Validation coverage (honest matrix)

Every rule has a **dev** anchor pair - a vulnerable PoC that must fire plus a safe implementation
that must stay silent. A **holdout** anchor is an *independent* fixture (a real-incident clone or a
canonical safe library) held out from the code the rule was written against, so the benchmark
measures generalization rather than memorization. Some real incident classes are honest
**non-fits** for the static layer: the mechanism is genuine but not statically decidable from the
contract's own source, so no anchor is wired - honesty over coverage, 0-FP over recall. The story
below was previously scattered across `validate/anchors.holdout.tsv` comments; this is the single
reviewer-facing summary (the anchor files remain the machine-checked source of truth).

Beyond these anchors, two **external cross-validations** against independent labelled corpora
measure agreement with an outside taxonomy (scanner-side runs, out of the benchmark, changing no
number): SWC-112 (`bench/external/swc-xval/` in wallet-harness) and SmartBugs-Curated
`access_control` ([`docs/external-xval/smartbugs-curated.md`](docs/external-xval/smartbugs-curated.md)
- 9/9 in-scope match on the delegatecall + init-hijack sub-families, 0 FP on the out-of-scope
entries).

| id | dev anchor | holdout anchor | documented non-fit (reason) |
|----|:----------:|:--------------:|-----------------------------|
| R1  | ✓ | safe only (Solady ERC20) | - |
| R2  | ✓ | safe only (Solady ERC721) | - |
| R3  | ✓ | safe only (Solady ERC20) | - |
| R4  | ✓ | - | **Anyswap permit-bypass**: a permit-*validation* bypass (router trusts a no-op permit on a token lacking one, then drains a pre-existing allowance), not "permit consumed beyond the action amount" - outside R4's shape, honestly skipped |
| R5  | ✓ | vuln + safe (Lixir / OZ permit) | - |
| R6  | ✓ | vuln + safe (Lixir / OZ permit + Solady ERC-1271) | - |
| R7  | ✓ | - | **Parity (2017)**: the proxy delegatecalls a FIXED immutable library; the bug is an unguarded `initWallet` in that library - a cross-contract fact not statically linkable from the proxy, and flagging every msg.data-forwarding proxy would FP on EIP-1167/UUPS. The unguarded-initializer root cause is now caught by **R12** (Parity is a wired R12 holdout-vuln); R7 stays the delegatecall enabler |
| R8  | ✓ | vuln (Inferno EIP-7702) | - |
| R9  | ✓ | - | **Tornado-governance-victim**: never references a code identity (`.codehash`), so R9 (fires only when a code identity is obtained but not enforced) correctly stays silent; its single-key pointer swap is captured by R10 instead |
| R10 | ✓ | vuln (Tornado metamorphic) | **Audius-governance-victim**: a re-callable unguarded `initialize` overwriting a `controller` role - not a swap of a live-logic pointer, so outside R10's shape. Now caught by **R12** (Audius is a wired R12 holdout-vuln); under R10 it stays an honest skip (different primitive) |
| R11 | ✓ (F2, DrainerKit) | - | **Squid**: pure arbitrary executor holding only *external* approvals (not visible in source) - F1-narrow correctly silent. **Pennysia**: the draining `transferFrom` lives in the attacker's calldata, not the Settlement's own code - neither F1-custody nor F2 matches (fit-checked by D, 2026-11-14) |
| R12 | safe only (OZ Timelock one-shot init) | vuln (Parity `initWallet` + Audius `initialize`) | - (scope extension overlapping R7/R10, not a 12th disjoint class - see note below) |
| R13 | ✓ | vuln + safe (Hedgey clone / OZ SafeERC20) | - |
| R14 | ✓ | vuln + safe (NFTTrader clone / Solady ERC721) | - |
| R15 | ✓ | vuln + safe (Sodium + Odos clones / OZ SignatureChecker) | - |

Legend: **✓** = a dev vuln+safe pair, anchored and asserted by `validate/all.sh`; **safe only** = a
*safe* fixture asserts 0-FP for the class but no *vuln* clone is wired at that split; **-** = none.
So holdout **vuln** anchors exist for R5, R6, R8, R10, R12, R13, R14, R15; R1/R2/R3 carry holdout *safe*
anchors only; R4, R7, R9, R11 are dev-anchored with the holdout-class incident documented as a non-fit
above. **R12 is the inverse shape**: both its real-incident vuln clones (Parity, Audius) are
*holdout* fixtures (authored after the v0.1 freeze, but known to the rule author - not blind),
and its 0-FP is asserted by a dev *safe*
anchor (the one-shot-guarded OZ Timelock) plus silence across all 193 real-safe files - so R12 has
no toy dev *vuln*, by design, since its vulnerable cases are the real incidents themselves.

Notes:
- R7's primitive (a `delegatecall` whose destination is attacker-settable) is a well-known
  check - drain-scan implements it on its own core taint pass over the solc AST, and does not
  claim the idea as novel. The value of drain-scan is the coherent, PoC-backed, wallet-focused
  bundle + the 0-FP-on-safe discipline, not detection novelty per rule.
- **R7 is stricter than SWC-112 (2020) by design.** A bare single-key *owner-settable*
  delegatecall target (no allow-list, no timelock+guardian) is treated as a drain surface - a
  rogue or compromised key can point it at a drainer, the same concern as R10's single-key
  upgrade. So R7 fires where SWC-112's 2020 samples call owner-control "fixed/safe" (cross-checked
  against the SWC Registry; see `bench/external/swc-xval/`). A **governed** target (allow-list, or
  timelock+guardian) and a canonical **fixed-slot proxy** (OZ UUPS/ERC-1967, where the
  implementation is governed, not an arbitrary parameter) stay silent - verified 0-FP across the
  real-safe corpus. R7/R8 also suppress the SWC-112 *mandatory-revert* pattern
  (`require(!ok)` on the delegatecall), which cannot persist state.
- R7, R8 and R11 overlap by design and are not claimed as distinct primitives: R7 (delegatecall-
  hijack) and R8 (AA/7702 forward) share one static primitive (a delegatecall to an attacker-
  settable target); R11 covers the plain-`call` / `transferFrom` arbitrary-callee case that R7/R8
  deliberately do not (a node is R11 **xor** R7/R8, never both). Each maps to its own vector and
  fixtures; the scanner de-duplicates per rule in its report.
- **R12 is a scope extension, not a 12th disjoint class** - it is called out so a reviewer is not
  told the corpus has one independent class per rule id. R12 overlaps R7 and R10: on Parity, R7 would catch
  the delegatecall *enabler* and R12 catches the unguarded-initializer *root cause* (R7 is a
  documented non-fit for Parity's fixed-library proxy, so in practice only R12 fires); on Audius,
  R10 reasons about the upgrade/governance authority surface and R12 pinpoints that the controller
  is settable by one unguarded call. R12's value is pinpointing the *who-gets-installed-as-authority*
  root cause independent of how the function is reached. It is deliberately **single-contract**:
  the authority-gate signal is read within one contract (a cross-contract proxy↔library split is
  R7's domain), so R12 leans on R7 for the delegatecall leg. Conservative by design - any modifier,
  any one-shot flag guard, or a constructor `_disableInitializers()` suppresses it - trading a
  possible false negative for the hard 0-FP (cf. the R11 narrow-variant roll-back).
- R11 holds a hard 0-FP (verified across the full real-safe corpus by `validate/zero_fp_probe.sh`).
  F1 (arbitrary call) runs only on a contract with a standing-approval *custody* signal and only
  from un-access-controlled entry points, so pure arbitrary executors - OpenZeppelin
  `TimelockController._execute`, and a bare multicall such as Squid - are not flagged. F2 (unbound
  `transferFrom`) is suppressed when the transfer is authorized (signature/permit or allowance
  accounting), so transfer proxies such as Permit2 are not flagged. Deliberate non-fits (honesty >
  coverage): the Squid arbitrary-executor class (holds only *external* approvals, not visible in
  source). (The "unprotected-initializer / init-hijack" class - Parity `initWallet`, Audius
  `initialize` - is no longer a non-fit: it ships as **R12**, above.)
- **R13 (unvalidated-approve-over-custody) is distinct from R1 and R3.** R1 keys on an *unbounded*
  amount (`type(uint256).max`) to a non-allowlisted spender - R13 fires even on a **bounded** amount,
  keying instead on the *spender* being a caller-supplied address the contract never validated while
  the contract custodies a *pooled* token balance (so a residual allowance drains other depositors'
  funds, not merely the caller's own deposit). R3 keys on an allowance left non-zero *after* a single
  function's action (missing reset) - a residual-hygiene weakness; R13 is about *who* is approved
  over pooled custody and fires at the moment of the grant, independent of whether a reset exists. A
  node can match R13 without R1 (amount is bounded) and without R3 (even if the allowance is later
  reset), so R13 needs no per-node de-dup against them; where the same `approve` is both unbounded
  and to an unvalidated custody spender, the scanner reports R1 and R13 as the separate surfaces they
  are (distinct fixes: pin the amount vs. allow-list the spender).
- **R14 (reentrancy / CEI approval-reuse) is distinct from R2 and R11.** R2 flags *granting*
  `setApprovalForAll` to an arbitrary operator; R11 flags an *arbitrary caller-supplied call*, or an
  unbound `transferFrom`, that spends a standing approval with no re-entrancy. R14 is a third
  primitive: the operator grant / approval is *legitimate*, and the drain is a re-entrant callback
  that re-targets it because effects are applied *after* the external call (a check-effects-
  interactions violation). R14 keys on the post-callback re-read of externally-mutable storage -
  which R2/R11 do not model - so it needs no per-node de-dup against them.
- **R15 (ERC-1271 forged-signer trust) is distinct from R5 and R6 - one signature cluster, three
  axes.** R5 (missing binding) and R6 (raw digest) both key on a direct `ecrecover` of an **EOA**
  signature: R5 on replay binding (deadline / nonce / domain), R6 on the digest being built via
  EIP-712 / ERC-1271 rather than a raw hash. R15 involves **no `ecrecover`** - it keys on a wallet
  trusting a signer *contract*'s `isValidSignature` (EIP-1271 magic `0x1626ba7e`) attestation: the
  axis is *who the signer contract is and whether its "valid" answer is trustworthy* (a
  caller-supplied/mutable signer, a permissive non-magic result, or an ERC-6492 deploy-and-trust).
  The three never overlap on a node (R5/R6 require the ecrecover predicate; R15 requires the 1271
  trust call), so no per-rule de-dup is needed. R15 additionally gates on an **asset sink**
  (transfer / approve / arbitrary call) as a precision discriminator: a caller-supplied signer is a
  *drain* only when its attestation authorizes moving funds - OZ `Governor.castVoteBySig` takes a
  caller-supplied `voter` but only records a vote (no asset sink), so it is correctly silent.
- PoC + safe anchors per rule live in the `wallet-harness` fixtures; the validation loop
  (`validate/`) asserts each rule fires on its vuln anchor and stays silent on its safe anchor,
  and `validate/zero_fp_probe.sh` asserts 0 findings across the whole real-safe corpus.
- **R5 nonce axis - enforcement-based (resolved):** R5 counts a nonce as present only when it is
  *enforced* - required-and-consumed (checked, then incremented), or woven into the verified EIP-712
  signed digest. A fixture that merely *declares* a nonce state-var / struct field without enforcing
  it is treated as replayable and **fires** R5 (no silent false negative). This closes the earlier
  declaration-vs-enforcement limitation; the domain and deadline axes are unchanged, all R5 anchors
  hold, and there is 0 FP across the real-safe corpus.
