"""drain-scan R11 - arbitrary-callee drain of a standing approval (NEW).

Engine: drain-scan core (solc AST, no Slither).

A contract that holds users' standing ERC-20 approvals and then makes an attacker-controlled
external move spends those approvals. Two shapes:

  F1  arbitrary external call: `target.call(data)` with target AND data both caller-supplied,
      no callee allow-list and no net-effect simulation, IN a contract that itself spends a
      standing approval (custody signal). Attacker passes target=token,
      data=transferFrom(victim, attacker, amt).
  F2  unbound transferFrom-shaped forward: a `transferFrom`/`safeTransferFrom` call whose
      `from` argument is a caller-supplied parameter NOT bound to msg.sender, with no
      authorization (permit/signature) in the call, no allow-list and no simulation - an
      unprivileged caller moves a third party's approved balance (DrainerKit.drain).

Scope (M-approved, variant B, 0-FP hard): F1 is NARROW - it fires only when the contract itself
holds/spends a standing approval; a pure arbitrary executor that holds no approval of its own (a
bare multicall like Squid, OZ TimelockController) is a documented NON-FIT, not an FP source.
F2 is bounded by three suppressions so legitimate code stays silent: (a) an in-call
permit/signature or allowance-accounting authorization (permit routers, Permit2, an ERC-20's own
transferFrom); (b) a `msg.sender == from` binding - direct, OR interprocedural for an internal
forwarder such as ERC4626 `deposit() -> _deposit(_msgSender(), ...)` - combined with a
funds-stay-here `address(this)` destination (a self-deposit, not a third-party drain); (c) an
address allow-list. Disjoint from R7/R8: F1 matches a plain `call` only; delegate-context
(delegatecall/callcode) belongs to R7/R8, never R11.

Anchors (validate/anchors.tsv; no holdout row - see the R11 NB in anchors.holdout.tsv):
  VULN  fixtures/malicious-calldata/b-incident/DrainerKitModule.sol  drain(victim) -> transferFrom(victim, self, bal)  [F2]
  SAFE  fixtures/malicious-calldata/c-safe-impl/SimulatedExecutor.sol  net-effect simulation
  SAFE  src/CalldataSafeWallet.sol  toy net-effect simulation guard
Static-layer NON-FITs (honest, not wired): Squid (pure executor - F1-narrow correctly silent);
Pennysia (executeSwap `venue.call(route)` - the draining transferFrom is in attacker calldata,
not in the Settlement's own code, so neither F1-custody nor F2 matches). See anchors.holdout.tsv.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # REPO_ROOT (core.*)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # detectors/ (_delegation)

from core.detector import Detector, Finding  # noqa: E402
from core.ast import node_type, member_name, call_callee, call_arguments  # noqa: E402
from core.dataflow import identifiers_read, taint_fixpoint  # noqa: E402
from _delegation import (  # noqa: E402
    CALL_MEMBERS,
    TRANSFERFROM_MEMBERS,
    addr_bool_mappings,
    member_calls,
    reads_allowlist,
    simulates_net_effect,
    function_authorizes,
    msg_sender_bound,
    f1_reachable_unguarded,
    contract_has_approval_custody,
    transfer_is_authorized,
    from_bound_to_sender,
    is_address_this,
    _unwrap_options,
)


class ArbitraryCalleeDrain(Detector):
    rule_id = "R11"
    argument = "drain-arbitrary-callee"
    name = "arbitrary-callee drain of a standing approval"
    help = "R11: an arbitrary external call / unbound transferFrom spends a standing approval, no allow-list/sim"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface or contract.is_library:
                continue
            if simulates_net_effect(contract):
                continue
            maps = addr_bool_mappings(contract)
            # Variant B (M 04:53): F1 fires ONLY when the contract itself spends a standing
            # approval (custody signal). A pure arbitrary executor (OZ TimelockController, a bare
            # multicall) has no custody of its own, so F1 stays silent on it. 0-FP > recall.
            has_custody = contract_has_approval_custody(contract)
            for function in contract.functions:
                if function.is_modifier:
                    continue
                params = set(function.parameter_names)
                tainted = taint_fixpoint(function, params)

                # ---- F1: arbitrary low-level call (target AND data caller-supplied) ----
                if has_custody:
                    for call, _m, dest in member_calls(function, CALL_MEMBERS):
                        if not (identifiers_read(dest) & tainted):
                            continue  # target not caller-supplied
                        if not any(identifiers_read(a) & tainted for a in call_arguments(call)):
                            continue  # calldata not caller-supplied
                        if maps and reads_allowlist(function, maps):
                            continue  # callee allow-list guard
                        if not f1_reachable_unguarded(contract, function):
                            continue  # access/role/timelock-gated entry (e.g. a governed executor)
                        findings.append(self._finding(contract, function, call,
                                                       "forwards an arbitrary caller-supplied call "
                                                       "(target+data) that can spend a standing approval (F1)"))

                # ---- F2: unbound transferFrom-shaped forward ----
                if transfer_is_authorized(function):
                    continue  # permit/signature OR allowance accounting authorizes the move (R4/R5/proxy)
                for call in function.calls():
                    callee = _unwrap_options(call_callee(call))
                    if node_type(callee) != "MemberAccess" or member_name(callee) not in TRANSFERFROM_MEMBERS:
                        continue
                    args = call_arguments(call)
                    if len(args) < 3:
                        continue
                    # `from`-candidates: bare parameter identifiers among all args but the last
                    # (the trailing arg is the amount/id), i.e. a caller-supplied source account.
                    from_names = [
                        a.get("name") for a in args[:-1]
                        if node_type(a) == "Identifier" and a.get("name") in params
                    ]
                    if not from_names:
                        continue
                    if msg_sender_bound(function, from_names):
                        continue  # caller bound to the source account -> authorized pull
                    if maps and reads_allowlist(function, maps):
                        continue
                    # Self-deposit suppression (M 12:17): a `from` bound to msg.sender (directly, or
                    # interprocedurally for an internal forwarder like ERC4626 `_deposit(_msgSender(),
                    # ...)`) moving funds INTO `address(this)` is the caller depositing their OWN assets,
                    # not a third party's standing approval being drained to an attacker. Both halves
                    # required: DrainerKit (from=victim!=sender) still fires. The `to` account is
                    # args[-2] (3-arg token.transferFrom or 4-arg library safeTransferFrom alike).
                    to_expr = args[-2]
                    if is_address_this(to_expr) and any(
                        from_bound_to_sender(contract, function, fn) for fn in from_names
                    ):
                        continue
                    findings.append(self._finding(contract, function, call,
                                                   "moves a caller-supplied account's approved "
                                                   "balance (unbound transferFrom) - standing-approval drain (F2)"))
        return findings

    def _finding(self, contract, function, call, message):
        return Finding(
            rule_id=self.rule_id,
            file=contract.source.name,
            line=contract.source.line_of(call),
            contract=contract.name,
            function=function.name,
            message=message,
        )
