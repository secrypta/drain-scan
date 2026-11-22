"""drain-scan R6: ecrecover over a raw/opaque digest not built via EIP-712 (blind eth_sign).

Flags a contract that authorizes from an `ecrecover` over a RAW digest - a bare `keccak256`
of packed/encoded data with no EIP-712 domain separator ("\\x19\\x01") and no typed-data
derivation. This is the blind-`eth_sign` / ERC-1271 drain surface: the owner signs an opaque
32-byte hash they cannot read, and the attacker chose what it commits to.

Conservative (0 FP is a hard requirement): fires only when a contract USES `ecrecover`
directly AND has no EIP-712 domain evidence. A contract that derives its digest as EIP-712
typed data is never flagged. Evaluated per contract, so a vuln and a safe contract in the same
file are scored independently (the anchors pin BlindSigWallet vuln / TypedSigWallet safe).

Why libraries are skipped: a reusable recovery primitive (OpenZeppelin `ECDSA`, Solady) is not
itself the drain surface - the surface is a contract that USES a signature to authorize asset
movement. OZ/Solady consumers recover *through* such a library, so they contain no direct
`ecrecover` and are silent by construction; the library (which does call ecrecover, with no
domain) is skipped. This is the 0-FP driver on the real OZ/Solady safe anchors.

Core port (solc AST, no Slither). The original Slither logic lived in
detectors/r6_ecrecover_raw_digest.py before the core migration (see git history); the
contract-level predicate (uses-ecrecover AND not has-EIP712-domain) is preserved exactly.
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name

# EIP-712 typed-data prefix bytes 0x19 0x01, in the two shapes solc's AST exposes a string
# literal: the decoded value (control chars) and the hexValue "1901...".
_EIP712_PREFIX_CHARS = "\x19\x01"


def _calls_ecrecover(contract):
    """True if any of the contract's own functions calls the `ecrecover` builtin directly."""
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


def _has_eip712_domain(contract):
    """Domain evidence, per contract: a DOMAIN_SEPARATOR-ish state var, an EIP712 base, an
    inline "\\x19\\x01" typed digest, or a `_hashTypedDataV4` call."""
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
                nm = member_name(callee) if node_type(callee) == "MemberAccess" else callee.get("name") if isinstance(callee, dict) else None
                if nm == "_hashTypedDataV4":
                    return True
    return False


class EcrecoverRawDigest(Detector):
    rule_id = "R6"
    argument = "drain-ecrecover-raw-digest"
    name = "ecrecover over a raw/opaque digest (blind eth_sign)"
    help = "ecrecover over a non-EIP-712 raw digest (R6)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue
            if not _calls_ecrecover(contract):
                continue
            if _has_eip712_domain(contract):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    file=contract.source.name,
                    line=contract.line,
                    contract=contract.name,
                    function=None,
                    message="recovers a signer from a raw, non-EIP-712 digest (blind eth_sign)",
                )
            )
        return findings
