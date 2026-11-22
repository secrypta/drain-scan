"""drain-scan R12: unprotected initializer / init-hijack.

Flags an externally-reachable function that installs an **authority role** of its contract
(the state variable the contract later uses to gate `msg.sender`) while being guarded by
*none* of: a modifier, a one-shot flag check, or an implementation lock. Such a function lets
anyone call it on the live contract, overwrite the privileged party with their own address, and
then exercise whatever that role gates (move funds, push a governance proposal, authorize a
malicious upgrade). This is the root cause behind the Parity multisig `initWallet` (2017) and
Audius Governance `initialize` (2022) takeovers.

Predicate (all three must hold for a function F in a `contract` C - interfaces/libraries skipped):

  1. Externally reachable  - F.visibility in {public, external}, not a constructor, not a modifier.
  2. Role-seizure          - F assigns a state variable V that is an *authority gate* of C, i.e.
                             V appears in a `msg.sender == V` / `msg.sender != V` comparison
                             anywhere in C. Authority is derived from how the contract *uses* V to
                             gate msg.sender, NOT from V's name (name-independent).
  3. Unprotected           - none of P1/P2/P3 holds:
                               P1  any modifier on F (covers OZ `initializer`/`reinitializer` and
                                   access control such as `onlyOwner`),
                               P2  a one-shot guard in the body: a require/assert (or `if(cond)
                                   revert`) whose condition reads a state variable F also writes
                                   (the check-a-flag-then-set-it idiom),
                               P3  C's constructor calls `_disableInitializers()` (OZ UUPS lock).

Conservative by design (0 false positives is a hard requirement): ANY modifier suppresses, ANY
flag-guard suppresses, an impl lock suppresses - a genuinely safe initializer is safe *precisely*
because it is one-shot, access-controlled, or locked, which is exactly P1/P2/P3. The predicate
encodes the security property, not a spelling. A borderline case is suppressed (possible false
negative) rather than risked as a false positive. 0-FP > recall.

Scope / honest overlap: R12 is a scope extension that overlaps R7 (controlled-delegatecall, the
Parity delegatecall *enabler*) and R10 (upgrade-governance authority) - it pinpoints the
*unguarded-initializer root cause* independent of how the function is reached - not a 12th
disjoint class. Single-contract reasoning: the gate signal is computed within one contract; a
cross-contract proxy/library split is R7's domain. See RULES.md#r12.

Engine: the drain-scan analysis core (solc AST, no Slither). Subclasses core.detector.Detector
exactly like detectors/r1_unbounded_approve.py and reads the AST through core.ast helpers only.
"""
from core.detector import Detector, Finding
from core.ast import (
    node_type,
    call_callee,
    call_arguments,
    iter_nodes,
)

GUARD_CALLS = ("require", "assert")


def _is_msg_sender(node):
    """True if `node` is the expression `msg.sender`."""
    if node_type(node) != "MemberAccess" or node.get("memberName") != "sender":
        return False
    base = node.get("expression", {})
    return node_type(base) == "Identifier" and base.get("name") == "msg"


def _identifier_names(root):
    """Every Identifier `name` anywhere under `root`."""
    return {
        n.get("name")
        for n in iter_nodes(root)
        if isinstance(n, dict) and n.get("nodeType") == "Identifier" and n.get("name")
    }


def _authority_gate_vars(contract, state_var_names):
    """State variables of C compared against msg.sender (`msg.sender == V` / `!= V`) anywhere
    in C. These are the authority gates whose seizure R12 cares about (name-independent)."""
    svs = set(state_var_names)
    gates = set()
    for node in contract.walk():
        if node_type(node) != "BinaryOperation" or node.get("operator") not in ("==", "!="):
            continue
        left = node.get("leftExpression", {})
        right = node.get("rightExpression", {})
        if _is_msg_sender(left):
            other = right
        elif _is_msg_sender(right):
            other = left
        else:
            continue
        gates |= _identifier_names(other) & svs
    return gates


def _written_state_vars(function, state_var_names):
    """State variables written by an Assignment in F (base identifier of the LHS)."""
    svs = set(state_var_names)
    written = set()
    for asn in function.assignments():
        written |= _identifier_names(asn.get("leftHandSide", {})) & svs
    return written


def _has_modifier(function):
    """P1: F carries any ModifierInvocation (access control or a one-call initializer modifier)."""
    mods = function.node.get("modifiers") or []
    return any(isinstance(m, dict) and m.get("nodeType") == "ModifierInvocation" for m in mods)


def _guard_reads(function):
    """State-var identifier names read inside a require/assert condition, or an `if(cond) revert`
    condition, in F - the read half of the check-a-flag-then-set-it one-shot idiom (P2)."""
    reads = set()
    for call in function.calls():
        callee = call_callee(call)
        if node_type(callee) == "Identifier" and callee.get("name") in GUARD_CALLS:
            args = call_arguments(call)
            if args:
                reads |= _identifier_names(args[0])
    for node in function.walk():
        if node_type(node) != "IfStatement":
            continue
        branches = [node.get("trueBody"), node.get("falseBody")]
        has_revert = any(
            node_type(n) == "RevertStatement"
            or (
                node_type(n) == "FunctionCall"
                and node_type(call_callee(n)) == "Identifier"
                and call_callee(n).get("name") == "revert"
            )
            for branch in branches
            if branch is not None
            for n in iter_nodes(branch)
        )
        if has_revert:
            reads |= _identifier_names(node.get("condition", {}))
    return reads


def _constructor_disables_init(contract):
    """P3: C's constructor calls `_disableInitializers()` (the OZ UUPS implementation lock)."""
    for function in contract.functions:
        if not function.is_constructor:
            continue
        for call in function.calls():
            callee = call_callee(call)
            if node_type(callee) == "Identifier" and callee.get("name") == "_disableInitializers":
                return True
    return False


class UnprotectedInitializer(Detector):
    rule_id = "R12"
    argument = "drain-unprotected-initializer"
    name = "unprotected initializer / init-hijack"
    help = "Externally-callable, unguarded function that installs an authority role (R12)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface or contract.is_library:
                continue
            state_vars = contract.state_variable_names()
            gate_vars = _authority_gate_vars(contract, state_vars)
            if not gate_vars:
                continue  # no msg.sender-gated authority in this contract -> nothing to seize
            impl_locked = _constructor_disables_init(contract)  # P3
            for function in contract.functions:
                if function.is_constructor or function.is_modifier:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                written = _written_state_vars(function, state_vars)
                seized = written & gate_vars
                if not seized:
                    continue
                # --- unprotected? suppressed by any of P1 / P3 / P2 ---
                if _has_modifier(function):            # P1: any modifier
                    continue
                if impl_locked:                        # P3: _disableInitializers in constructor
                    continue
                if _guard_reads(function) & written:   # P2: one-shot flag guard
                    continue
                # flag at the seizing assignment for precision (fall back to the function line)
                line = function.line
                for asn in function.assignments():
                    if _identifier_names(asn.get("leftHandSide", {})) & seized:
                        line = contract.source.line_of(asn) or line
                        break
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file=contract.source.name,
                        line=line,
                        contract=contract.name,
                        function=function.name,
                        message=(
                            "installs an authority role (%s) with no re-init guard, modifier, or "
                            "access control - anyone can call it and seize the role"
                            % ", ".join(sorted(seized))
                        ),
                    )
                )
        return findings
