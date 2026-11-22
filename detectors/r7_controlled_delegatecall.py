"""drain-scan R7 - controlled delegatecall (delegatecall-hijack).

Vector (wal corpus): delegatecall-hijack.  Engine: drain-scan core (solc AST, no Slither).

A wallet/account that `delegatecall`s a destination the attacker can set - a call parameter,
or a storage pointer written by an un-gated setter - runs hostile code in the account's own
storage/asset context. Flipping an `operation` flag to delegatecall or installing a hostile
delegate overwrites the logic pointer and sweeps the account (the Bybit Safe class).

OWN CODE (not a wrapper). v1 subclassed Slither's `controlled-delegatecall`; v2 re-derives the
condition over the solc AST: a delegatecall/callcode whose destination identifier is tainted
from a parameter OR is a state variable with an un-gated writer, minus the three defenses the
safe fixtures use (allowlist / net-effect simulation / governed proxy). See core/_delegation.

Anchors (validate/anchors.tsv):
  VULN  src/VulnerableAccount.sol                                 execTransaction -> to.delegatecall (`to` param, unguarded)
        fixtures/delegatecall-hijack/b-incident/BybitSafeClone.sol  operation-flag delegatecall, no allowlist
  SAFE  src/SafeAccount.sol                                       delegatecall gated by allowedDelegate[to] + revert
        fixtures/delegatecall-hijack/c-safe-impl/GuardedExecutor.sol  allow-listed delegatecall target
        fixtures/malicious-calldata/c-safe-impl/SimulatedExecutor.sol  net-effect simulation
        src/CalldataSafeWallet.sol                                net-effect simulation (toy)
        src/SafeUpgradeWallet.sol                                 governed proxy: impl written only via timelock+guardian
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # REPO_ROOT (core.*)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # detectors/ (_delegation)

from core.detector import Detector, Finding  # noqa: E402
from _delegation import delegate_hijack_findings  # noqa: E402


class ControlledDelegatecall(Detector):
    rule_id = "R7"
    argument = "drain-controlled-delegatecall"
    name = "controlled delegatecall (delegatecall-hijack)"
    help = "R7: delegatecall to a mutable / attacker-settable target in a wallet/account"

    def detect(self, unit):
        def make(contract, function, call):
            return Finding(
                rule_id=self.rule_id,
                file=contract.source.name,
                line=contract.source.line_of(call),
                contract=contract.name,
                function=function.name,
                message="delegatecalls a mutable / attacker-settable target (delegatecall-hijack)",
            )
        return delegate_hijack_findings(unit, make)
