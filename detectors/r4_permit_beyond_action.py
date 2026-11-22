"""drain-scan R4: permit/Permit2 consumed beyond the action amount.

A consumer (relayer/router/wallet) that submits a user's signed `permit` (EIP-2612) or a
Permit2 authorization, and then pulls MORE than the interaction needs - the owner's full
balance, or an unbounded `type(uint256).max` - rather than exactly the action amount. A
permit phished for a large/unbounded value plus a consumer that spends the whole balance is
the full drain.

Signal (per function): the function CONSUMES a permit (a call to `permit` / Permit2
`permitTransferFrom` / `permitWitnessTransferFrom`) AND performs a `transferFrom` /
`safeTransferFrom` (token member form or the SafeERC20 static library form that real routers
use) whose amount is a full-balance sweep (derived from a `balanceOf(...)` read) or the
unbounded maximum (`type(uint256).max`). A consumer that transfers a bounded action amount (a
parameter / fixed value) is NOT flagged.

Conservative (0-FP): only functions that both consume a permit and move a full-balance /
unbounded amount are flagged. A scoped consumer that pulls exactly the action amount is
silent, and a token that merely DEFINES permit (never calls it) is not a candidate.

Core rewrite (solc AST, no Slither): the balanceOf -> amount link uses core.dataflow's light
name-level taint; ordering is not required (the two calls co-occur in the function).
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, call_callee, call_arguments, iter_nodes
from core.dataflow import assignment_pairs, taint_fixpoint, identifiers_read

UINT256_MAX = (1 << 256) - 1
PERMIT_NAMES = ("permit", "permitTransferFrom", "permitWitnessTransferFrom")
# The pull sink, recognized across the token member form and the SafeERC20 static library
# form. `transferFrom` is token-native; `safeTransferFrom` appears both as `token.safeTransferFrom
# (from,to,amount)` (member) and `SafeERC20.safeTransferFrom(token,from,to,amount)` (static, one
# extra leading `token`). The transferred amount is the last positional argument in every form.
TRANSFER_SINK_NAMES = ("transferFrom", "safeTransferFrom")


def _callee_name(call):
    """The called member/identifier name of a FunctionCall, or None."""
    callee = call_callee(call)
    if node_type(callee) == "MemberAccess":
        return member_name(callee)
    if node_type(callee) == "Identifier":
        return callee.get("name")
    return None


def _contains_balanceof(node):
    for n in iter_nodes(node):
        if isinstance(n, dict) and n.get("nodeType") == "MemberAccess" and n.get("memberName") == "balanceOf":
            return True
    return False


def _is_uint_max(node):
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "MemberAccess" and node.get("memberName") == "max":
        inner = node.get("expression", {})
        if node_type(inner) == "FunctionCall":
            c = inner.get("expression", {})
            if (node_type(c) == "Identifier" and c.get("name") == "type") or \
               node_type(c) == "ElementaryTypeNameExpression":
                return True
    if node.get("nodeType") == "Literal" and node.get("kind") == "number":
        try:
            return node.get("value") is not None and int(node["value"]) == UINT256_MAX
        except (TypeError, ValueError):
            return False
    return False


def _balance_tainted_names(function):
    """Names of locals assigned (transitively) from a balanceOf(...) read."""
    seeds = set()
    for lhs_names, rhs in assignment_pairs(function):
        if _contains_balanceof(rhs):
            seeds |= {n for n in lhs_names if n}
    if not seeds:
        return set()
    return taint_fixpoint(function, seeds)


class PermitBeyondAction(Detector):
    rule_id = "R4"
    argument = "drain-permit-beyond-action"
    name = "permit consumed beyond the action amount"
    help = "Permit/Permit2 consumed then full-balance/unbounded transferFrom (R4)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface:
                continue
            for function in contract.functions:
                calls = function.calls()
                consumes_permit = any(_callee_name(c) in PERMIT_NAMES for c in calls)
                if not consumes_permit:
                    continue

                tainted = _balance_tainted_names(function)
                flagged = None
                for call in calls:
                    name = _callee_name(call)
                    if name not in TRANSFER_SINK_NAMES:
                        continue
                    args = call_arguments(call)
                    # Static SafeERC20.safeTransferFrom(token, from, to, amount) prepends `token`;
                    # the member transferFrom/safeTransferFrom(from, to, amount) does not. The
                    # amount is the last positional argument in both forms.
                    if name == "safeTransferFrom" and len(args) >= 4:
                        amount = args[3]
                    elif len(args) >= 3:
                        amount = args[2]
                    else:
                        continue
                    full_balance = bool(identifiers_read(amount) & tainted) or _contains_balanceof(amount)
                    if full_balance or _is_uint_max(amount):
                        flagged = call
                        break
                if flagged is not None:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            file=contract.source.name,
                            line=contract.source.line_of(flagged),
                            contract=contract.name,
                            function=function.name,
                            message="consumes a permit then transferFrom a full-balance/unbounded amount, beyond the action",
                        )
                    )
        return findings
