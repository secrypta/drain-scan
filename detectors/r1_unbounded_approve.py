"""drain-scan R1: unbounded approve to an arbitrary spender.

Flags an ERC-20 `approve(spender, amount)` (or `increaseAllowance`) where `amount` is the
unbounded maximum (`type(uint256).max`) AND `spender` is arbitrary (not a hard-coded address
literal). Unbounded allowance to a non-fixed spender is the classic approve-drainer enabler:
the extra, unused allowance stays live and lets a spender pull the whole balance later.

Conservative by design (0 false positives is a hard requirement): a *bounded* approve
(amount != max) is never flagged, and an unbounded approve to a *hard-coded* address literal
(a fixed, audited counterparty) is not flagged either - only unbounded + arbitrary-spender.

This is the reference detector on the drain-scan core (solc AST, no Slither). It reads the
AST through core.ast helpers and the shared approve-family recognizer in
detectors/_delegation.py (`member_calls` + `approve_spender_amount`), so it matches the
approve across both source forms: a token member call (`token.approve` /
`token.safeApprove(spender, amount)`) and the SafeERC20 / TransferHelper static library form
(`SafeERC20.safeApprove(token, spender, amount)`, operands shifted right by one - the shape
real victims actually use). The amount and spender arguments are then tested as before.
"""
from core.detector import Detector, Finding
from core.ast import node_type
from detectors._delegation import member_calls, approve_spender_amount, APPROVE_FAMILY_MEMBERS

UINT256_MAX = (1 << 256) - 1


def _amount_is_unbounded(amount):
    """type(uint256).max, in either of its AST shapes."""
    if not isinstance(amount, dict):
        return False
    # Shape A: `type(uint256).max` -> MemberAccess(memberName="max") over the FunctionCall
    #          `type(uint256)`, whose callee is the built-in `type` identifier (the uint256
    #          sits in its arguments). Some solc versions model the callee as an
    #          ElementaryTypeNameExpression instead; accept both.
    if amount.get("nodeType") == "MemberAccess" and amount.get("memberName") == "max":
        inner = amount.get("expression", {})
        if node_type(inner) == "FunctionCall":
            callee = inner.get("expression", {})
            if (node_type(callee) == "Identifier" and callee.get("name") == "type") or \
               node_type(callee) == "ElementaryTypeNameExpression":
                return True
    # Shape B: a folded integer literal equal to 2**256-1.
    if amount.get("nodeType") == "Literal" and amount.get("kind") == "number":
        val = amount.get("value")
        try:
            if val is not None and int(val) == UINT256_MAX:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _spender_is_arbitrary(spender):
    """A hard-coded address literal is a fixed, audited counterparty -> not arbitrary.
    Anything else (a parameter, a storage var, a computed value) is arbitrary."""
    if not isinstance(spender, dict):
        return True
    return spender.get("nodeType") != "Literal"


class UnboundedApprove(Detector):
    rule_id = "R1"
    argument = "drain-unbounded-approve"
    name = "unbounded approve to arbitrary spender"
    help = "Unbounded approve/increaseAllowance to an arbitrary spender (R1)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface:
                continue  # an interface only declares approve(); it never calls it
            for function in contract.functions:
                # Recognize the approve across both source forms: a token member call
                # (`token.approve`/`token.safeApprove(spender, amount)`) and the SafeERC20 /
                # TransferHelper static library form (`SafeERC20.safeApprove(token, spender,
                # amount)`, operands shifted right by one). The shared recognizer in
                # detectors/_delegation.py normalizes the spender/amount positions, so the
                # library-static call shape used by real victims (Anyswap TransferHelper,
                # Hedgey SafeERC20) is no longer invisible to R1.
                for call, member, _receiver in member_calls(function, APPROVE_FAMILY_MEMBERS):
                    spender, amount = approve_spender_amount(member, call)
                    if spender is None or amount is None:
                        continue
                    if _amount_is_unbounded(amount) and _spender_is_arbitrary(spender):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                file=contract.source.name,
                                line=contract.source.line_of(call),
                                contract=contract.name,
                                function=function.name,
                                message="approves an unbounded amount (type(uint256).max) to an arbitrary spender",
                            )
                        )
        return findings
