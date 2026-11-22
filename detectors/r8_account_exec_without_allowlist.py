"""drain-scan R8 - account forwards delegate execution to a calldata target, no allowlist.

Vector (wal corpus): eip7702-delegation / malicious-calldata.  Engine: drain-scan core (AST).

An account-abstraction (ERC-4337) account or EIP-7702 delegate runs module/delegate code "as
the account" (in the account's own storage/asset context). If it installs or forwards to a
target taken from calldata (a parameter, or a storage pointer set by an un-gated setter) with
no allow-list of audited targets, a phished authorization or a mislabeled module drains the
account in one call (CrimeEnjoyor-style 7702 sweeper; drainer-kit "execute by label").

Relation to R7 (stated plainly). R7 and R8 share one static primitive: a delegatecall whose
destination is attacker-settable (implemented once in core/_delegation.delegate_hijack_findings
and validated by both rules' anchors). R7 is the delegatecall-hijack framing; R8 is the AA/7702
framing and maps to different wal vectors and fixtures. The overlap is deliberate and
documented (RULES.md) - neither is claimed as a novel primitive; drain-scan's value is the
coherent, PoC-backed, 0-FP-disciplined bundle.

Anchors (validate/anchors.tsv):
  VULN  src/CalldataVulnerableWallet.sol   executeByLabel -> module.delegatecall (`module` param, label trusted)
        src/DelegationVector.sol           VulnerableDelegationAccount.activate (delegate set by un-gated installDelegation)
  SAFE  fixtures/eip7702-delegation/c-safe-impl/AllowlistedDelegatePolicy.sol  allow-listed audited delegate only
        fixtures/malicious-calldata/c-safe-impl/SimulatedExecutor.sol          net-effect simulation
        src/CalldataSafeWallet.sol                                            net-effect simulation (toy)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # REPO_ROOT (core.*)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # detectors/ (_delegation)

from core.detector import Detector, Finding  # noqa: E402
from _delegation import delegate_hijack_findings  # noqa: E402


class AccountExecWithoutAllowlist(Detector):
    rule_id = "R8"
    argument = "drain-account-exec-without-allowlist"
    name = "account forwards delegate execution to a calldata target, no allowlist"
    help = "R8: AA/7702 account forwards delegate execution to a calldata-supplied target with no allow-list"

    def detect(self, unit):
        def make(contract, function, call):
            return Finding(
                rule_id=self.rule_id,
                file=contract.source.name,
                line=contract.source.line_of(call),
                contract=contract.name,
                function=function.name,
                message="forwards delegate execution to a calldata-supplied target with no allow-list (AA/7702)",
            )
        return delegate_hijack_findings(unit, make)
