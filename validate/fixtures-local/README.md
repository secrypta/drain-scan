# validate/fixtures-local - first-party demonstrations (not wal-corpus anchors)

Local, authored toy fixtures used to demonstrate a detector change in isolation, without
touching the shared wallet-harness corpus (`anchors.tsv` / `anchors.holdout.tsv`, which M/D
curate). These are **synthetic** (clearly labelled in each file's PROVENANCE header), not real
incidents.

## R5 - enforcement-based nonce (declared vs enforced)

R5 previously treated a nonce as present when any `nonce`-named declaration existed anywhere in
the contract. A contract that *declares* a nonce but never checks, consumes, or binds it is
still replayable, so that was a false negative. R5 now counts a nonce only when it is actually
**enforced** - (a) checked against stored state **and** consumed, or (b) woven into the signed
EIP-712 digest.

| fixture | nonce | expected R5 |
|---|---|---|
| `DeclaredNonceIgnoredSettlement.sol` | declared, never enforced | **FIRE** (replayable) |
| `EnforcedNonceSettlement.sol` | checked + consumed + in digest | **silent** |

The vulnerable case is the new catch: under the old declaration-based logic it was silent
(false negative); it now fires. The safe companion isolates the enforcement distinction - the
same contract, nonce enforced, stays silent.

### Reproduce

```bash
. .venv/bin/activate
solc-select use 0.8.24
./scan validate/fixtures-local/DeclaredNonceIgnoredSettlement.sol   # 1 finding: [R5]
./scan --no-fail validate/fixtures-local/EnforcedNonceSettlement.sol # 0 findings
```

No regression on the wal corpus:

```bash
WAL_ROOT=~/wal validate/all.sh          # DEV + HOLDOUT p/r/F1 = 1.0
WAL_ROOT=~/wal validate/zero_fp_probe.sh # 0 FP on all 193 safe files
```
