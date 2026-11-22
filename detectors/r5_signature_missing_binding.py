"""drain-scan R5: auth signature verified without replay binding (no nonce / no domain).

Flags a contract that authorizes asset movement from an `ecrecover` check but does NOT bind
that signature against replay: it lacks a nonce (single-use) AND/OR a domain separator
(EIP-712 contract/chain binding). Such a signature can be replayed - on the same contract (no
nonce) or on a clone / another chain (no domain) - to drain repeatedly.

Conservative (0 FP is a hard requirement): fires only when the contract USES `ecrecover`
directly AND is missing a nonce OR a domain separator. A deadline alone is a mitigation, not a
replay binding, so its absence is not sufficient to fire; a contract with BOTH a nonce and a
domain separator is never flagged. Libraries/interfaces are skipped (a reusable recovery
primitive like OZ `ECDSA` is not the drain surface - the consumer recovers through it and
contains no direct `ecrecover`, so OZ/Solady safe anchors are silent by construction).

Core port (solc AST, no Slither). Preserves the original Slither predicate (see git history,
detectors/r5_signature_missing_binding.py before the core migration): uses-ecrecover AND NOT
(has-domain AND has-nonce). R5/R6 share the domain test; R5 adds the nonce axis.

Nonce axis is ENFORCEMENT-based (not declaration-based). A contract that merely DECLARES a
`nonce` state-var / struct field but never checks, consumes or binds it is still replayable,
so a bare declaration no longer counts as a nonce. The nonce is treated as present only when
it is actually enforced - either (a) checked against the stored value (a `require`/`if`
comparison) AND consumed (an increment, or marked used in a mapping), or (b) woven into the
EIP-712 digest that `ecrecover` verifies (the signed value carries the nonce). See `_has_nonce`.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, iter_nodes, nodes_of_type

_EIP712_PREFIX_CHARS = "\x19\x01"

# Comparison operators that count as a nonce check (`require(a.nonce == d.nonce)` etc.).
_COMPARISON_OPS = {"==", "!=", "<", "<=", ">", ">="}
# Increment/decrement operators that count as consuming a nonce (`nonces[owner]++`).
_CONSUME_UNARY_OPS = {"++", "--"}
# Hashing/encoding primitives that build the signed digest; a nonce reference inside their
# arguments means the nonce is bound into what `ecrecover` verifies.
_DIGEST_CALLEES = {"keccak256", "encode", "encodePacked", "encodeWithSelector", "encodeWithSignature"}


def _calls_ecrecover(contract):
    for function in contract.functions:
        for call in function.calls():
            callee = call.get("expression", {})
            if node_type(callee) == "Identifier" and callee.get("name") == "ecrecover":
                return True
    return False


def _literal_is_eip712_prefix(node):
    if node_type(node) != "Literal":
        return False
    if _EIP712_PREFIX_CHARS in (node.get("value") or ""):
        return True
    return (node.get("hexValue") or "").lower().startswith("1901")


def _has_domain(contract):
    for name in contract.state_variable_names():
        if "domainseparator" in name.lower().replace("_", ""):
            return True
    for base in contract.node.get("baseContracts", []) or []:
        bname = ((base.get("baseName") or {}).get("name") or "")
        if "eip712" in bname.lower():
            return True
    for function in contract.functions:
        for n in function.walk():
            if _literal_is_eip712_prefix(n):
                return True
            if node_type(n) == "FunctionCall":
                callee = n.get("expression", {})
                nm = member_name(callee) if node_type(callee) == "MemberAccess" else (callee.get("name") if isinstance(callee, dict) else None)
                if nm == "_hashTypedDataV4":
                    return True
    return False


def _name_is_nonce(name):
    """A declared name that carries replay state: contains `nonce` (nonces/usedNonce/...)."""
    return bool(name) and "nonce" in name.lower()


def _refs_nonce(node):
    """True if `node`'s subtree references a nonce-named *variable* (Identifier/MemberAccess).

    Deliberately ignores string Literals, so a typehash string that merely spells "nonce"
    (e.g. `keccak256("Order(...,uint256 nonce)")`) does NOT count - only a real nonce value
    flowing through the expression (`d.nonce`, `nonces[owner]`, `usedNonce[nonce]`) does.
    """
    for n in iter_nodes(node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "Identifier" and _name_is_nonce(n.get("name")):
            return True
        if nt == "MemberAccess" and _name_is_nonce(n.get("memberName")):
            return True
    return False


def _nonce_in_signed_digest(contract):
    """(b) The nonce is woven into the signed digest: a nonce value appears inside the
    arguments of a hashing/encoding primitive (keccak256 / abi.encode[Packed]), i.e. the value
    `ecrecover` verifies carries the nonce (EIP-712 / EIP-2612 style)."""
    for call in nodes_of_type(contract.node, "FunctionCall"):
        callee = call.get("expression", {})
        nt = node_type(callee)
        if nt == "Identifier":
            name = callee.get("name")
        elif nt == "MemberAccess":
            name = member_name(callee)
        else:
            name = None
        if name in _DIGEST_CALLEES:
            for arg in call.get("arguments", []) or []:
                if _refs_nonce(arg):
                    return True
    return False


def _nonce_checked(contract):
    """Part of (a): the nonce is checked against stored state - a comparison against a nonce
    value (`a.nonce != d.nonce`, `o.nonce == nonces[owner]`) or a `!usedNonce[...]` guard."""
    for n in iter_nodes(contract.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "BinaryOperation" and n.get("operator") in _COMPARISON_OPS and _refs_nonce(n):
            return True
        if nt == "UnaryOperation" and n.get("operator") == "!" and _refs_nonce(n.get("subExpression")):
            return True
    return False


def _nonce_consumed(contract):
    """Part of (a): the nonce is consumed so a signature cannot be reused - an increment
    (`nonces[owner]++`) or an assignment to a nonce lvalue (`a.nonce = d.nonce + 1`,
    `usedNonce[nonce] = true`)."""
    for n in iter_nodes(contract.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "UnaryOperation" and n.get("operator") in _CONSUME_UNARY_OPS and _refs_nonce(n.get("subExpression")):
            return True
        if nt == "Assignment" and _refs_nonce(n.get("leftHandSide")):
            return True
    return False


def _has_nonce(contract):
    # ENFORCEMENT-based (not declaration-based). A bare declaration of a `nonce` var/field is
    # NOT enough: a contract that declares a nonce but never checks, consumes or binds it is
    # still replayable (the same signature settles forever). The nonce counts as present only
    # when it is actually enforced:
    #   (a) checked against the stored nonce (require/if comparison) AND consumed (increment or
    #       marked used in a mapping), OR
    #   (b) woven into the EIP-712 digest that ecrecover verifies (the signed value carries it).
    # Current anchors: BoundSettlement/ToyPermit2/MockERC20/Settlement/ClearSigningWallet all
    # weave the nonce into the digest (and consume it) -> enforced -> R5 stays silent. The Lixir
    # incident clone also enforces its nonce (digest + increment) and fires only on the missing
    # domain axis. A declared-but-ignored nonce satisfies neither branch -> R5 FIRES (replayable).
    if _nonce_in_signed_digest(contract):
        return True
    return _nonce_checked(contract) and _nonce_consumed(contract)


class SignatureMissingBinding(Detector):
    rule_id = "R5"
    argument = "drain-signature-missing-binding"
    name = "auth signature missing replay binding (nonce/domain)"
    help = "ecrecover auth without nonce/domain replay binding (R5)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue
            if not _calls_ecrecover(contract):
                continue
            has_domain = _has_domain(contract)
            has_nonce = _has_nonce(contract)
            if has_domain and has_nonce:
                continue
            missing = []
            if not has_domain:
                missing.append("domain separator")
            if not has_nonce:
                missing.append("nonce")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    file=contract.source.name,
                    line=contract.line,
                    contract=contract.name,
                    function=None,
                    message="authorizes via ecrecover without replay binding; missing " + ", ".join(missing),
                )
            )
        return findings
