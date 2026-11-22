"""drain-scan R3: lingering allowance (approve for an action, no reset afterwards).

Flags a function that grants a non-zero ERC-20 allowance (the approve family:
`approve`/`increaseAllowance`/`safeApprove`/`forceApprove`/`safeIncreaseAllowance`, recognized
in both the token member form and the SafeERC20 / TransferHelper static library form via the
shared recognizer in detectors/_delegation.py) and then performs a further external call that
uses it, but never resets the allowance back to zero in the same function. The unused
remainder of the allowance lingers and can be swept later (the residual-allowance drain
surface).

Conservative (0 FP is a hard requirement): fires only when ALL of
  * a non-zero approve-family grant is present,
  * there is a later external call in the same function (the allowance is actually used), and
  * there is NO reset-to-zero (an approve-family grant of amount 0) anywhere in the function.
A function that approves and resets to zero, or that only approves without using it, is not
flagged. (Unbounded approves are R1's job; R3 is the bounded-but-not-reset hygiene gap.)

Core rewrite (solc AST, no Slither): ordering is taken from each call's byte offset in the
`src` field (lexical order), since the compact AST lists statements in source order.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, call_callee
from detectors._delegation import approve_spender_amount, APPROVE_FAMILY_MEMBERS


def _offset(node):
    try:
        return int(node["src"].split(":")[0])
    except (KeyError, ValueError, IndexError, TypeError):
        return -1


def _is_zero(arg):
    return (
        isinstance(arg, dict)
        and arg.get("nodeType") == "Literal"
        and arg.get("kind") == "number"
        and str(arg.get("value")) == "0"
    )


class LingeringAllowance(Detector):
    rule_id = "R3"
    argument = "drain-lingering-allowance"
    name = "lingering allowance (no reset after action)"
    help = "Non-zero approve used by a later external call, never reset to zero (R3)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface:
                continue
            for function in contract.functions:
                nonzero_approve_offsets = []
                has_reset = False
                ext_use_offsets = []
                for call in function.calls():
                    callee = call_callee(call)
                    if node_type(callee) != "MemberAccess":
                        continue  # casts / free calls are not the approve or the external use
                    m = member_name(callee)
                    if m in APPROVE_FAMILY_MEMBERS:
                        # Normalize the grant across member and SafeERC20/TransferHelper static
                        # forms (the library call shape real victims use) via the shared
                        # recognizer, so the lingering-allowance surface is seen in both forms.
                        _spender, amount = approve_spender_amount(m, call)
                        if amount is not None and _is_zero(amount):
                            has_reset = True
                        else:
                            nonzero_approve_offsets.append(_offset(call))
                        continue
                    # any other external member call is a candidate "use" of the allowance
                    # (includes transferFrom / safeTransferFrom - the library-form use-side)
                    ext_use_offsets.append(_offset(call))

                if not nonzero_approve_offsets or has_reset:
                    continue
                first_approve = min(nonzero_approve_offsets)
                if any(o > first_approve for o in ext_use_offsets):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            file=contract.source.name,
                            line=function.line,
                            contract=contract.name,
                            function=function.name,
                            message="grants an allowance and never resets it to zero after the action",
                        )
                    )
        return findings
