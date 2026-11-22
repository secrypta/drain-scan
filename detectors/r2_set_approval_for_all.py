"""drain-scan R2: setApprovalForAll(operator, true) to an arbitrary operator.

Flags an ERC-721/1155 `setApprovalForAll(operator, true)` where `operator` is arbitrary (not
a hard-coded address literal). Blanket operator approval hands standing authority over the
wallet's ENTIRE collection to the operator; a malicious/compromised operator can then sweep
every token. The scoped alternative (`approve(operator, tokenId)`) is not flagged.

Conservative (0 FP is a hard requirement): only `approved == true` to a non-literal operator
is flagged. `setApprovalForAll(op, false)` (a revoke) and approvals to a fixed address literal
are never flagged.

Core rewrite (solc AST, no Slither): a FunctionCall whose callee is `.setApprovalForAll` with
a literal `true` second argument and a non-literal first argument.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, call_callee, call_arguments


def _is_true_literal(node):
    return (
        isinstance(node, dict)
        and node.get("nodeType") == "Literal"
        and (node.get("kind") == "bool" or node.get("value") in ("true", "false"))
        and node.get("value") == "true"
    )


def _operator_is_arbitrary(node):
    # A hard-coded address literal is a fixed, audited operator -> not arbitrary.
    if not isinstance(node, dict):
        return True
    return node.get("nodeType") != "Literal"


class SetApprovalForAllArbitrary(Detector):
    rule_id = "R2"
    argument = "drain-set-approval-for-all"
    name = "setApprovalForAll to arbitrary operator"
    help = "setApprovalForAll(operator, true) to an arbitrary operator (R2)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface:
                continue
            for function in contract.functions:
                for call in function.calls():
                    callee = call_callee(call)
                    if node_type(callee) != "MemberAccess":
                        continue
                    if member_name(callee) != "setApprovalForAll":
                        continue
                    args = call_arguments(call)
                    if len(args) < 2:
                        continue
                    operator, approved = args[0], args[1]
                    if _is_true_literal(approved) and _operator_is_arbitrary(operator):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                file=contract.source.name,
                                line=contract.source.line_of(call),
                                contract=contract.name,
                                function=function.name,
                                message="grants blanket setApprovalForAll(operator, true) to an arbitrary operator",
                            )
                        )
        return findings
