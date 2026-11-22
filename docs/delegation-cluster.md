# Delegation cluster - R7 & R8

Two rules about the same drain surface: **code that runs in the account's own storage/asset
context** (delegatecall, EIP-7702 delegates, AA module execution). When the target of that
execution is attacker-influenced and unconstrained, one call takes over or empties the wallet.

| id | flags | vector (wal) | engine | severity |
|----|-------|--------------|--------|----------|
| R7 | delegatecall to a mutable / attacker-settable target | delegatecall-hijack | core | high |
| R8 | account forwards delegate execution to a calldata-supplied target with no allow-list | eip7702-delegation / malicious-calldata | core | high |

## The shared primitive (stated plainly)

R7 and R8 rest on **one** primitive in our **own** core: a taint check over the solc AST
(`core.dataflow`) for whether a `delegatecall` / account-exec destination is attacker-settable -
no Slither, no SlithIR. We verified on the wallet-harness anchors that this
primitive, on its own, fires on **every** fixture in the cluster - the vulnerable ones *and*
the genuinely-safe ones (`SafeAccount`, `SafeDelegationAccount`, `SimulatedExecutor`), because
the destination is tainted in all of them. So the taint check is necessary but nowhere near
sufficient: **the entire value of these rules is on the safe side** - recognizing the defense
and staying silent (drain-scan's hard requirement: a rule that fires on genuinely-safe code is
not shipped).

R7 and R8 therefore overlap by design. We do not present either as a novel detection:

- **R7 is own code, not a wrapper.** It re-derives the `controlled-delegatecall` *pattern* on our
  own solc-AST taint - it does **not** import or wrap Slither (Slither is AGPL; drain-scan is MIT).
  As with every rule, we do not claim the detection *idea* is new; the contribution is the
  coherent own-engine, PoC-backed, 0-FP-disciplined bundle plus the rule ⇄ fixture ⇄ benchmark
  methodology.
- **R8** is the AA/EIP-7702 framing of the same primitive, with two differences that earn it a
  separate rule: it also covers the *delegate-installed-by-an-un-gated-setter* shape (a storage
  pointer, not just a parameter), and it must stay silent on a **second** defense that R7 never
  meets - net-effect simulation.

## The 0-FP layer: recognizing the defenses

Raw taint fires on safe code, so each finding is suppressed when a recognized defense is
present. The defenses are exactly the ones the corpus's safe fixtures use (see
`detectors/_delegation_guards.py`):

### (1) Allowlist membership guard - R7 and R8

An `mapping(address => bool)` is consulted, and the call reverts on a miss, before the
destination is reached:

- **destination is a parameter** -> the forwarding function itself indexes the allowlist keyed
  by that parameter and can revert. *Anchor:* `SafeAccount` - `if (!allowedDelegate[to]) revert`.
- **destination is a storage pointer** -> *every* (non-constructor) function that writes that
  pointer gates membership + reverts. *Anchor:* `SafeDelegationAccount.installDelegation` -
  `require(allowlisted[delegate_])`. An un-gated setter (`VulnerableDelegationAccount`) is not
  suppressed, so R8 still fires.

### (2) Net-effect simulation guard - R8 only

The contract snapshots an ERC-20 balance/allowance, runs the delegate action, re-reads the
value, and reverts on an adverse change - so a hidden `approve`/`transfer` is rolled back. This
is a **runtime** defense (the Fire / Blockaid / Pocket Universe / Wallet Guard class), which
drain-scan's README otherwise scopes *out* as transaction-time screening. But the reference
fixture `SimulatedExecutor` is genuinely-safe real code, and the 0-FP requirement is absolute,
so R8 recognizes the pattern statically and stays silent on it.

The signal is **contract-level**, because the real reference impl splits the pattern across two
functions: `executeSimulated` snapshots-before then commits via delegatecall, while `probe`
delegatecalls then reads-after and reverts. A contract that reads balanceOf/allowance both
before and after a delegate call and can revert is, by construction, measuring and gating its
net asset effect. The forwarding vuln anchors read no balances, so this never masks them - and
the validation loop re-checks that on every run.

> These suppressions are conservative heuristics, not a soundness proof. They are *validated*,
> not asserted: `validate/anchors.tsv` ties each rule to the labeled PoC it must catch and the
> safe code it must not flag, and `validate/run.sh` fails CI on any FP/FN. A future fixture that
> breaks a heuristic will turn the loop red - that is the methodology working as intended.

## Anchors & validation

```
RULE  LABEL  FIXTURE
R7    vuln   src/VulnerableAccount.sol                                   (toy: unguarded `to` param)
R7    vuln   fixtures/delegatecall-hijack/b-incident/BybitSafeClone.sol  (incident: Bybit operation-flag flip)
R7    safe   src/SafeAccount.sol                                         (toy: allow-list guard)
R7    safe   fixtures/delegatecall-hijack/c-safe-impl/GuardedExecutor.sol(c-safe: canonical allow-list)
R8    vuln   src/CalldataVulnerableWallet.sol                            (toy: delegatecall a module param)
R8    vuln   src/DelegationVector.sol                                    (toy: 7702 un-gated delegate install)
R8    safe   fixtures/eip7702-delegation/c-safe-impl/AllowlistedDelegatePolicy.sol (c-safe: allow-list)
R8    safe   fixtures/malicious-calldata/c-safe-impl/SimulatedExecutor.sol        (c-safe: net-effect simulation)
R8    safe   src/CalldataSafeWallet.sol                                  (toy: net-effect simulation)
```

```bash
WAL_ROOT=/path/to/wallet-harness validate/run.sh R7
WAL_ROOT=/path/to/wallet-harness validate/run.sh R8
# current: R7 TP=2 FP=0 FN=0 TN=2 ; R8 TP=2 FP=0 FN=0 TN=3 ; precision=recall=1.000
```

## How to fix (what the rule wants to see)

- **R7 / R8 - allow-list the target.** Restrict delegate/module execution to an allow-list of
  audited addresses and revert otherwise. Never delegatecall a raw call parameter or a storage
  pointer set by an un-gated setter. For EIP-7702, refuse to install any delegate that is not
  allow-listed; for AA accounts, constrain the executable target set.
- **R8 - or simulate the net effect.** If an allow-list is impractical, dry-run the action and
  revert on any unexpected balance/allowance change (what `SimulatedExecutor` does). This is a
  runtime defense; pair it with transaction-screening rather than relying on static review.
