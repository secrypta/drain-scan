"""drain-scan R10: unguarded upgrade - implementation/module/delegate swap with no timelock.

Flags a function that swaps the wallet's implementation/module/delegate/logic slot (a direct
state-variable assignment, e.g. `implementation = newImplementation`) with NO timelock/delay
guard in that same function body. If a single key can call it, one compromised key = instant
malicious upgrade = full drain (the attacker swaps in a hostile implementation and the next
delegatecall sweeps the wallet).

This is the semantic sibling of the shipped Semgrep rule `R10'` (which stays as a syntactic
cross-check): the Semgrep rule matches the swap/guard *shape*; this core detector resolves it
over the AST and additionally observes the single-key + no-guardian condition for the message.

Conservative (0 FP is a hard requirement):
  - Only a real Assignment (`x = ...`) to a slot-named state variable counts - a local
    `address impl = implementation;` (a VariableDeclarationStatement) does NOT, so the common
    proxy-fallback idiom is not mistaken for a swap.
  - A swap function that contains a `block.timestamp` delay check (require/if timelock) is
    silent - a two-step propose/delay/apply upgrade is safe.
  - Real OZ UUPS (ERC-1967) writes the implementation through `StorageSlot...value = impl`
    (LHS is a `.value` MemberAccess, not a slot-named identifier) and gates it on an external
    TimelockController, so it has no slot-named assignment to match and is silent by
    construction - the c-safe anchor proves this.
Libraries/interfaces are skipped.

Core detector (solc AST, no Slither); R10 had no Slither detector (Semgrep-only) before, so
this is a fresh port of the R10' predicate to the core, strengthened with the guardian check.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, identifier_name, call_callee, iter_nodes

# Role names that denote a NON-single-key upgrade authority: a swap gated by a check against
# one of these (an on-chain governance/guardian/authority/timelock role) is NOT the R10 defect
# ("a single key can instantly swap"), so R10 stays silent on it. `owner`/`admin` are
# deliberately EXCLUDED - an owner-/admin-gated instant swap is exactly the vuln surface (one
# compromised key = instant malicious upgrade), and every R10 vuln anchor is owner-gated.
_AUTHORITY_ROLES = {
    "governance", "governor", "guardian", "authority",
    "timelock", "council", "dao", "multisig", "securitycouncil",
}

# External-authority decision calls: a swap gated by deferring to an external authority
# contract's access decision (e.g. OpenZeppelin AccessManager's `canCall`) is governance-gated.
_AUTHORITY_CALLS = {"cancall", "checkcanupgrade"}

# impl/module/logic slot names (optionally underscore-prefixed), matched exactly.
# NB: `delegate` is deliberately NOT here - an EIP-7702 / account-abstraction `delegate`
# pointer is R8's domain (account exec / delegation policy), not an upgrade-governance slot.
# Including it made R10 bleed into the delegation vector and fire on the allow-list-guarded
# safe delegation pattern (R8's safe case) - a cross-vector false positive. R10 stays scoped to
# implementation/module/logic/proxy upgrade pointers; the delegation cluster (R7/R8) owns `delegate`.
_SLOT_NAMES = {"implementation", "impl", "module", "logic", "proxy"}


def _is_slot_name(name):
    if not name:
        return False
    return name.lstrip("_").lower() in _SLOT_NAMES


def _lhs_name(assignment):
    lhs = assignment.get("leftHandSide", {})
    if node_type(lhs) == "Identifier":
        return lhs.get("name")
    # `this.implementation = ...` / `self.impl = ...`: a MemberAccess whose member is the slot.
    if node_type(lhs) == "MemberAccess":
        return member_name(lhs)
    return None


def _function_has_timelock(function):
    """A delay/timelock guard in the function body: any `block.timestamp` reference (as the
    Semgrep R10' rule keys on `require(block.timestamp >= ...)` / `if (block.timestamp < ...)`)."""
    for n in function.walk():
        if node_type(n) == "MemberAccess" and member_name(n) == "timestamp":
            base = n.get("expression", {})
            if identifier_name(base) == "block":
                return True
    return False


def _contract_has_guardian(contract):
    return any("guardian" in (nm or "").lower() for nm in contract.state_variable_names())


def _norm(name):
    return (name or "").lstrip("_").lower()


def _is_authority_role(name):
    return _norm(name) in _AUTHORITY_ROLES


def _is_msg_sender(node):
    """True iff `node` is the expression `msg.sender`."""
    return (
        node_type(node) == "MemberAccess"
        and member_name(node) == "sender"
        and identifier_name(node.get("expression", {})) == "msg"
    )


def _node_side_name(node):
    """Role name referenced by `node` (an Identifier or a `.member` MemberAccess)."""
    if node_type(node) == "Identifier":
        return node.get("name")
    if node_type(node) == "MemberAccess":
        return member_name(node)
    return None


def _gate_roots(contract, function):
    """The AST sub-trees that can carry `function`'s access gate: its own body, the bodies of
    the modifiers it applies, and the bodies of the (same-contract) internal helpers it calls
    (one level - e.g. OZ AccessManaged's `_restricted()`). Resolved over the AST, by name,
    within this contract only."""
    roots = [function.node]
    by_name = {f.name: f for f in contract.functions}

    # modifiers applied to the function (ModifierInvocation -> ModifierDefinition body)
    for inv in function.node.get("modifiers", []) or []:
        mname = (inv.get("modifierName") or {}).get("name") if isinstance(inv, dict) else None
        target = by_name.get(mname)
        if target is not None and target.is_modifier:
            roots.append(target.node)

    # internal helper calls in the body (FunctionCall with an Identifier callee -> its def)
    for call in function.calls():
        cname = identifier_name(call_callee(call))
        target = by_name.get(cname)
        if target is not None and not target.is_modifier and not target.is_constructor:
            roots.append(target.node)
    return roots


def _has_authority_gate(contract, function):
    """True iff `function` is gated by a non-single-key authority: a `msg.sender == <role>`
    check against a governance/guardian/authority/timelock role, or a deferral to an external
    authority decision (e.g. AccessManager.canCall). Owner/admin gates are NOT authority gates
    (they are the R10 defect), so they are not matched here and the swap still fires."""
    for root in _gate_roots(contract, function):
        for n in iter_nodes(root):
            nt = node_type(n)
            # (1) external authority decision: `...canCall(...)` / `...checkCanUpgrade(...)`
            if nt == "FunctionCall":
                callee = call_callee(n)
                if node_type(callee) == "MemberAccess" and _norm(member_name(callee)) in _AUTHORITY_CALLS:
                    return True
            # (2) `msg.sender == <authority role>` (either operand order)
            if nt == "BinaryOperation" and n.get("operator") == "==":
                left, right = n.get("leftExpression", {}), n.get("rightExpression", {})
                if _is_msg_sender(left) and _is_authority_role(_node_side_name(right)):
                    return True
                if _is_msg_sender(right) and _is_authority_role(_node_side_name(left)):
                    return True
    return False


class UnguardedUpgrade(Detector):
    rule_id = "R10"
    argument = "drain-unguarded-upgrade"
    name = "implementation/module swap without timelock/guardian"
    help = "Instant single-key implementation/module/delegate swap, no timelock (R10)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue
            guarded_by_guardian = _contract_has_guardian(contract)
            for function in contract.functions:
                # The constructor's `implementation = implementation_` is one-time
                # initialization at deploy, not a post-deployment upgrade swap - never the
                # drain surface. The defect is a swap reachable AFTER deploy.
                if function.is_constructor:
                    continue
                swap = next(
                    (a for a in function.assignments()
                     if a.get("operator") == "=" and _is_slot_name(_lhs_name(a))),
                    None,
                )
                if swap is None:
                    continue
                if _function_has_timelock(function):
                    continue
                # Silent when the swap is gated by a non-single-key authority (on-chain
                # governance / guardian / timelock role, or a deferral to an external authority
                # decision like AccessManager.canCall) - that is not the single-key instant-swap
                # defect. Owner/admin gates are NOT authority gates and still fire.
                if _has_authority_gate(contract, function):
                    continue
                extra = "" if guarded_by_guardian else " (single-key, no guardian)"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file=contract.source.name,
                        line=contract.source.line_of(swap),
                        contract=contract.name,
                        function=function.name,
                        message="swaps the implementation/module slot with no timelock delay" + extra,
                    )
                )
        return findings
