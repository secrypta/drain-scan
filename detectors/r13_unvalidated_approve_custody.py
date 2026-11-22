"""drain-scan R13: approve to an unvalidated caller-supplied spender over pooled custody.

Flags a contract that holds a token balance of its own (pooled custody) and grants an ERC-20
`approve` / `forceApprove` / `safeApprove` / `increaseAllowance` to a spender that is
attacker-influenced (a function parameter or a caller-supplied struct field) and NOT validated
(no address-allowlist membership gate, not bound to `msg.sender`). The residual, unrevoked
allowance then lets that spender `transferFrom` the contract's whole pooled balance - the exact
code-level flaw behind the Hedgey Finance drain (2024-04-19, ~$44.7M): `createLockedCampaign`
pulled a deposit into `address(this)` and then `token.approve(locker, amount)` where `locker`
was an unvalidated campaign-supplied address.

This is a SEPARATE drain surface from the other approve rules, deliberately scoped so the three
do not overlap:
  - R1 (unbounded-approve) keys on `amount == type(uint256).max`; R13 fires on a BOUNDED approve
    too (Hedgey's `amount` was bounded), so R1 stays silent on it.
  - R3 (lingering-allowance) keys on "approve + action + no reset-to-zero in one wallet"; the
    Hedgey-class defect is approve-on-create to an unvalidated spender over a POOLED balance, a
    custody/validation flaw, not a missing single-function reset.
The distinguishing signal R13 adds over R1 is (custody + attacker-supplied spender + no gate),
independent of the amount.

Core detector (solc AST, no Slither). It reuses the delegation/calldata cluster's shared AST
helpers (detectors/_delegation.py): the approve-family member-call scan, the pooled-custody
signal (`contract_has_approval_custody`), the address-allowlist gate recognizer
(`is_allowlist_guarded`), and the msg.sender-binding and taint primitives.

0-false-positives is a hard requirement, carried by two independent conditions that every real
safe fixture in the corpus fails to meet simultaneously:
  (1) POOLED CUSTODY - the contract itself moves third-party tokens (`transferFrom`) or keeps an
      allowance of its own. The canonical bounded-approve helpers (OZ SafeERC20 `forceApprove`
      wrapper, Solady `safeApprove` wrapper, a scoped ERC721 `approve` policy) are STATELESS -
      they forward an approve on a token they do not hold, so they have no custody and R13 stays
      silent. A token implementation (OZ/Solady ERC20) has an `allowance` of its own but writes
      it by internal assignment (`allowance[...] = x`), never an external `.approve(...)` call,
      so there is no approve-family member call to match.
  (2) ATTACKER-SUPPLIED + UNVALIDATED SPENDER - the spender is a function parameter (or derived
      from one) with no allowlist-membership gate and not bound to `msg.sender`. A fixed
      (immutable/constant/in-code) counterparty is not taint-reachable from the parameters, so a
      "approve the audited router" policy over real custody is silent; a `msg.sender`-bound or
      allowlist-gated spender is silent too.
Libraries/interfaces are skipped.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, call_callee, call_arguments, nodes_of_type
from core.dataflow import taint_fixpoint, identifiers_read
from detectors._delegation import (
    member_calls,
    contract_has_approval_custody,
    is_allowlist_guarded,
    msg_sender_bound,
    expr_is_msg_sender,
    is_address_this,
    approve_spender_amount,
    APPROVE_FAMILY_MEMBERS,
)


def _src_offset(node):
    """Start byte-offset from a node's `src` ('offset:len:file'), or -1."""
    if not isinstance(node, dict) or not node.get("src"):
        return -1
    try:
        return int(node["src"].split(":")[0])
    except (ValueError, IndexError):
        return -1


def _is_zero_literal(node):
    return isinstance(node, dict) and node_type(node) == "Literal" and node.get("value") == "0"


def _allowance_zero_cmp(expr, spender_ids, want_op):
    """True if `expr` contains a BinaryOperation `<want_op>` (e.g. `==` or `!=`) comparing an
    `allowance(address(this), <spender>)` call - whose second argument reads exactly `spender_ids`
    - against a literal 0. The spender-identifier match (e.g. `c.tokenLocker`) keeps an unrelated
    allowance check from matching."""
    for cmp in [expr] + nodes_of_type(expr, "BinaryOperation"):
        if node_type(cmp) != "BinaryOperation" or cmp.get("operator") != want_op:
            continue
        left, right = cmp.get("leftExpression", {}), cmp.get("rightExpression", {})
        if _is_zero_literal(left):
            other = right
        elif _is_zero_literal(right):
            other = left
        else:
            continue
        for fc in [other] + nodes_of_type(other, "FunctionCall"):
            if node_type(fc) != "FunctionCall":
                continue
            callee = call_callee(fc)
            if node_type(callee) != "MemberAccess" or member_name(callee) != "allowance":
                continue
            aargs = call_arguments(fc)
            if len(aargs) >= 2 and is_address_this(aargs[0]) and identifiers_read(aargs[1]) == spender_ids:
                return True
    return False


def _branch_reverts(body):
    """True if `body` (an if-branch) contains a `revert`/`revert(...)` - a RevertStatement or a call
    to the `revert` builtin."""
    for n in [body] + nodes_of_type(body, "RevertStatement") + nodes_of_type(body, "FunctionCall"):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "RevertStatement":
            return True
        if n.get("nodeType") == "FunctionCall":
            c = call_callee(n)
            if node_type(c) == "Identifier" and c.get("name") == "revert":
                return True
    return False


def _asserts_zero_residual(function, approve_call, spender_ids):
    """True if, AFTER the approve, the same function ENFORCES that the approved allowance is fully
    consumed back to zero, so no residual standing allowance survives the call (R13's premise - a
    residual, unrevoked allowance an attacker later drains - is void).

    ENFORCEMENT is required, not mere presence (audit F1): the zero-residual check must be able to
    REVERT the transaction, via
      - `require(... allowance(address(this), spender) == 0 ...)` / `assert(...)`   (reverts if residual remains), or
      - `if (... allowance(address(this), spender) != 0 ...) { revert }`             (same, inverted).
    A bare, unenforced `allowance(...) == 0` - a dead expression, a logged/`view`-returned value, an
    unused local - does NOT suppress: it cannot stop a live residual from being drained, so R13 must
    still fire. Mirrors `_delegation.delegatecall_result_must_revert`. The real hardened Hedgey
    ClaimCampaigns uses the `require(... == 0 ...)` form right after the locker pulls the tokens; the
    genuine vulnerable version has no such enforcement, so it still fires. Spender matched by
    identifier set, so an unrelated allowance check does not suppress."""
    if not spender_ids:
        return False
    approve_off = _src_offset(approve_call)
    # (1) require(...)/assert(...) whose condition asserts allowance(this, spender) == 0
    for n in nodes_of_type(function.node, "FunctionCall"):
        if _src_offset(n) <= approve_off:
            continue
        callee = call_callee(n)
        if node_type(callee) == "Identifier" and callee.get("name") in ("require", "assert"):
            args = call_arguments(n)
            if args and _allowance_zero_cmp(args[0], spender_ids, "=="):
                return True
    # (2) if (allowance(this, spender) != 0) { revert } - reverts when a residual remains
    for n in nodes_of_type(function.node, "IfStatement"):
        if _src_offset(n) <= approve_off:
            continue
        if _branch_reverts(n.get("trueBody", {})) and _allowance_zero_cmp(n.get("condition", {}), spender_ids, "!="):
            return True
    return False

# ERC-20 allowance-granting members. The spender argument is read form-agnostically via
# `approve_spender_amount` (member form `token.safeApprove(spender,..)` spender=args[0]; SafeERC20
# static library form `SafeERC20.safeIncreaseAllowance(token,spender,..)`, which the real Hedgey
# drain uses, spender=args[1]). `safeIncreaseAllowance` is now covered - it was the missed form.
APPROVE_MEMBERS = APPROVE_FAMILY_MEMBERS


def _spender_is_attacker_supplied(spender, tainted):
    """The approved spender is attacker-influenced: a parameter (or a value derived from one,
    e.g. a caller-supplied struct field `input.locker`), and NOT a fixed counterparty.

    Excluded (a fixed / self counterparty, never the R13 defect):
      - an address literal (a hard-coded, audited address),
      - `msg.sender` / `_msgSender()` (the caller approving itself),
      - `address(this)` (self),
      - anything whose identifiers are not reachable from the function's parameters - a
        constant/immutable/in-code spender (e.g. an audited `immutable router`) is written only
        at construction, so it is never in the parameter-seeded taint set.
    """
    if not isinstance(spender, dict):
        return False
    if node_type(spender) == "Literal":
        return False
    if expr_is_msg_sender(spender) or is_address_this(spender):
        return False
    return bool(identifiers_read(spender) & tainted)


class UnvalidatedApproveOverCustody(Detector):
    rule_id = "R13"
    argument = "drain-unvalidated-approve-custody"
    name = "approve to an unvalidated caller-supplied spender over pooled custody"
    help = "Pooled-custody contract approves an unvalidated attacker-supplied spender (R13)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue
            # Condition (1): the contract holds a token balance of its own. A stateless approve
            # forwarder (no custody) is never the Hedgey-class pooled-drain surface.
            if not contract_has_approval_custody(contract):
                continue
            state_vars = set(contract.state_variable_names())
            for function in contract.functions:
                if function.is_modifier:
                    continue
                tainted = taint_fixpoint(function, set(function.parameter_names))
                for call, _member, receiver in member_calls(function, APPROVE_MEMBERS):
                    # Approving on `this`/`address(this)` is not an outward grant of custody.
                    if is_address_this(receiver):
                        continue
                    # Read the spender form-agnostically (member args[0] vs static-library args[1]).
                    spender, _amount = approve_spender_amount(_member, call)
                    if spender is None:
                        continue
                    # Condition (2a): spender attacker-influenced (parameter-derived), not fixed.
                    if not _spender_is_attacker_supplied(spender, tainted):
                        continue
                    # Condition (2b): spender is validated -> silent.
                    spender_ids = identifiers_read(spender)
                    if msg_sender_bound(function, spender_ids):
                        continue
                    spender_state_vars = spender_ids & state_vars
                    if is_allowlist_guarded(contract, function, spender_ids, spender_state_vars):
                        continue
                    # Condition (2c): the function asserts zero residual allowance after the grant
                    # (`require/assert allowance(address(this), spender) == 0`) -> the standing
                    # allowance R13 keys on is consumed and checked back to zero, so there is
                    # nothing residual to drain -> silent (real hardened Hedgey; genuine vuln has none).
                    if _asserts_zero_residual(function, call, spender_ids):
                        continue
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            file=contract.source.name,
                            line=contract.source.line_of(call),
                            contract=contract.name,
                            function=function.name,
                            message=(
                                "grants an approval to an unvalidated caller-supplied spender "
                                "over a pooled token balance (residual allowance drains custody)"
                            ),
                        )
                    )
        return findings
