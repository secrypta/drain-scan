"""drain-scan R15: ERC-1271 forged / permissive signer trust (contract-signature drain).

Flags a wallet/account that authorizes asset movement from an ERC-1271 `isValidSignature`
attestation made by a signer *contract* it does not actually control. The drained wallet asks
some address "is this signature valid?" and moves funds when that address says yes - but the
address (or the way its answer is read) lets an attacker manufacture the "yes".

AXIS - this is deliberately distinct from the other two signature-cluster rules:
  * R5 (missing-binding) and R6 (raw-digest) are about `ecrecover` of an **EOA** signature:
    replay binding and the shape of the signed digest. Their predicate REQUIRES a direct
    `ecrecover` call.
  * R15 is about trusting a **signer contract's** `isValidSignature` attestation (EIP-1271 magic
    `0x1626ba7e`). No `ecrecover` is involved. The axis is: *who is the signer contract, and is
    its "valid" answer trustworthy?*

Three concrete forms (per the rule spec); R15 fires on any:
  (i)  signer-is-attacker-controlled: the address whose `isValidSignature` is trusted comes from
       caller-supplied / mutable input (a function parameter, or a value decoded from calldata)
       rather than an immutable / allow-listed signer. An attacker names their own permissive
       contract, which returns the magic for anything. (Lumi/Sodium, 2026 - see the b-incident.)
  (ii) result-interpreted-permissively: a direct (or low-level) `isValidSignature` call whose
       answer is NOT strictly required to equal the ERC-1271 magic value - the wallet authorizes
       on a bare non-revert / `staticcall` success, so a signer that returns garbage (or simply
       does not revert) is accepted. (The Gnosis-Pay class.)
  (iii) ERC-6492 counterfactual deploy-and-trust: during signature validation the wallet deploys,
       or low-level-calls, a caller-supplied factory/verifier and then trusts its attestation.
       (The Odos class, 2025 - see the b-incident.)

0-FP is a hard requirement (signature-cluster = high FP risk; canonical OZ/Solady ERC-1271 code
is everywhere). Silence is guaranteed for the real safe corpus because, there, every 1271 trust
call either targets an IMMUTABLE / internally-configured signer (`OzSignatureCheckerWallet`'s
immutable `signer`, Solady's `_erc1271Signer()`) AND reads the answer strictly (OZ/Solady helpers
compare against the magic internally). Reusable recovery/checker primitives are LIBRARIES
(OZ `SignatureChecker`, Solady `SignatureCheckerLib`, Permit2 `SignatureVerification`) and are
skipped - the drain surface is the consumer, not the primitive.

The asset-sink requirement is a genuine precision discriminator, not a fixture-fit. A
caller-supplied signer is only a DRAIN when its attestation gates moving assets. OpenZeppelin
`Governor.castVoteBySig` verifies a signature for a `voter` passed as a parameter (so the signer
IS caller-supplied) but it only RECORDS that voter's own vote and moves no funds - no asset sink,
no drain, correctly silent. The same caller-supplied-signer shape becomes a finding only when the
function also transfers/approves/arbitrary-calls (Lumi/Sodium `approve`, Odos arbitrary `call`,
the toys' `transfer`). See `_has_asset_sink` / `_ASSET_SINKS`.

Core port (solc AST, no Slither).
"""
from core.detector import Detector, Finding
from core.ast import node_type, member_name, iter_nodes, nodes_of_type

# ERC-1271 magic value: bytes4(keccak256("isValidSignature(bytes32,bytes)")).
_MAGIC_HEX = "1626ba7e"
# Checker-helper functions that perform the 1271 trust call internally and whose FIRST argument
# is the trusted signer address (OZ SignatureChecker / Solady SignatureCheckerLib). A helper does
# the strict magic comparison itself, so a helper call is never "permissive result" (axis ii) -
# but it IS a 1271 trust call, so axis (i) (attacker-controlled signer arg) still applies.
_CHECKER_HELPERS = {
    "isValidSignatureNow",
    "isValidSignatureNowCalldata",
    "isValidERC1271SignatureNow",
    "isValidERC1271SignatureNowCalldata",
}
# Low-level dispatch members that carry an arbitrary payload to the signer address.
_LOWLEVEL = {"staticcall", "call"}
_ENCODERS = {"encodeWithSelector", "encodeCall", "encodeWithSignature"}
# Asset-moving / authority-granting sinks. R15 is a DRAIN rule: a forged/permissive signer is
# only dangerous when its attestation gates MOVING ASSETS (or an arbitrary call). A function that
# merely attributes an action to the signer itself and moves nothing - e.g. OZ Governor's
# `castVoteBySig`, which records a vote for the `voter` whose signature it checked - is NOT a drain
# and must stay silent even though its signer is a parameter. `staticcall` is excluded: it is how
# the 1271 attestation is READ, not an asset move.
_ASSET_SINKS = {
    "transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "approve", "safeApprove",
    "forceApprove", "increaseAllowance", "setApprovalForAll", "send", "sendValue",
    "call", "delegatecall", "mint", "burnFrom", "withdraw",
}


# ------------------------------- small AST helpers -------------------------------

def _callee(call):
    return call.get("expression", {}) or {}


def _callee_member(call):
    """The member name if the call is `recv.member(...)`, else None."""
    c = _callee(call)
    return member_name(c) if node_type(c) == "MemberAccess" else None


def _callee_ident(call):
    """The plain name if the call is `name(...)` (Identifier callee), else None."""
    c = _callee(call)
    return c.get("name") if node_type(c) == "Identifier" else None


def _unwrap_type_conversion(node):
    """`IERC1271(x)` is a FunctionCall type-conversion; return its inner `x`. Otherwise `node`."""
    if node_type(node) == "FunctionCall" and node.get("kind") == "typeConversion":
        args = node.get("arguments") or []
        if args:
            return args[0]
    return node


def _is_magic_literal(node):
    if node_type(node) != "Literal":
        return False
    hv = (node.get("hexValue") or "").lower()
    if hv.endswith(_MAGIC_HEX) or hv == _MAGIC_HEX:
        return True
    return _MAGIC_HEX in (node.get("value") or "").lower()


def _is_magic_selector(node):
    """A `.selector` member access on something named isValidSignature (IERC1271.isValidSignature
    .selector), i.e. the ERC-1271 magic expressed symbolically."""
    if node_type(node) != "MemberAccess" or member_name(node) != "selector":
        return False
    inner = node.get("expression", {}) or {}
    return "isvalidsignature" in (member_name(inner) or "").lower() if node_type(inner) == "MemberAccess" else False


def _mentions_magic(node):
    for n in iter_nodes(node):
        if isinstance(n, dict) and (_is_magic_literal(n) or _is_magic_selector(n)):
            return True
    return False


def _magic_const_ids(unit):
    """Declaration ids of constants initialized to the ERC-1271 magic value (`bytes4 constant
    MAGIC = 0x1626ba7e;`), so a strict comparison written against the NAMED constant still counts
    as a magic check - not just a comparison against the bare literal."""
    ids = set()
    for sf in unit.sources:
        for n in iter_nodes(sf.ast):
            if isinstance(n, dict) and n.get("nodeType") == "VariableDeclaration" and n.get("id") is not None:
                val = n.get("value")
                if isinstance(val, dict) and _is_magic_literal(val):
                    ids.add(n["id"])
    return ids


def _is_magic_operand(node, magic_ids):
    if not isinstance(node, dict):
        return False
    if _is_magic_literal(node) or _is_magic_selector(node):
        return True
    return node.get("nodeType") == "Identifier" and node.get("referencedDeclaration") in magic_ids


# ----------------------------- caller-controllability -----------------------------

def _param_decl_ids(func_node):
    out = set()
    for p in ((func_node.get("parameters") or {}).get("parameters") or []):
        if isinstance(p, dict) and p.get("id") is not None:
            out.add(p["id"])
    return out


def _local_ids_from_params(func_node, param_ids):
    """Declaration ids of local variables whose initializer references a parameter (one level):
    e.g. `address signer = abi.decode(signature[1:21], (address));` - `signer` becomes tainted
    because its initializer reads the `signature` parameter. This is the calldata-decode path the
    Lumi/Sodium account took (the signer is named inside the attacker's own signature blob)."""
    tainted = set()
    # iterate to a small fixpoint so a local fed from another tainted local is also caught
    changed = True
    while changed:
        changed = False
        for decl in nodes_of_type(func_node, "VariableDeclarationStatement"):
            init = decl.get("initialValue")
            if not init:
                continue
            if _refs_ids(init, param_ids | tainted):
                for d in (decl.get("declarations") or []):
                    if isinstance(d, dict) and d.get("id") is not None and d["id"] not in tainted:
                        tainted.add(d["id"])
                        changed = True
    return tainted


def _refs_ids(node, id_set):
    for n in iter_nodes(node):
        if isinstance(n, dict) and n.get("nodeType") == "Identifier" and n.get("referencedDeclaration") in id_set:
            return True
    return False


def _signer_is_caller_controlled(func_node, signer_expr):
    """True if the signer address expression traces to a function parameter or to a local decoded
    from one. Immutable/constant state vars and internal getters (`_erc1271Signer()`) are NOT
    parameters, so the real safe anchors (immutable `signer`, `owner`) never match."""
    if signer_expr is None:
        return False
    param_ids = _param_decl_ids(func_node)
    if not param_ids:
        return False
    tainted = param_ids | _local_ids_from_params(func_node, param_ids)
    return _refs_ids(signer_expr, tainted)


# ------------------------------- 1271 trust calls -------------------------------

def _trust_calls(func_node):
    """Yield (call_node, signer_expr, kind) for every ERC-1271 trust call in the function.
    kind in {'direct','helper','lowlevel'}; signer_expr is the trusted-signer address node."""
    out = []
    for call in nodes_of_type(func_node, "FunctionCall"):
        member = _callee_member(call)
        ident = _callee_ident(call)
        args = call.get("arguments") or []
        # direct: recv.isValidSignature(hash, sig)  (recv may be `IERC1271(x)`)
        if member == "isValidSignature":
            recv = _callee(call).get("expression", {}) or {}
            out.append((call, _unwrap_type_conversion(recv), "direct"))
            continue
        # helper: Lib.isValidSignatureNow(signer, ...) / using-for signer.isValidSignatureNow(...)
        if member in _CHECKER_HELPERS or ident in _CHECKER_HELPERS:
            # library-style first arg is the signer; using-for style the receiver is the signer
            if args:
                out.append((call, args[0], "helper"))
            elif member in _CHECKER_HELPERS:
                out.append((call, (_callee(call).get("expression", {}) or {}), "helper"))
            continue
        # low-level: signer.staticcall(abi.encode...(isValidSignature/magic, ...))
        if member in _LOWLEVEL and _payload_targets_1271(args):
            recv = _callee(call).get("expression", {}) or {}
            out.append((call, recv, "lowlevel"))
    return out


def _payload_targets_1271(args):
    """A low-level call's payload encodes the ERC-1271 selector / isValidSignature."""
    for a in args:
        for n in iter_nodes(a):
            if not isinstance(n, dict) or n.get("nodeType") != "FunctionCall":
                continue
            nm = _callee_member(n)
            if nm in _ENCODERS or nm == "abi":
                if _mentions_magic(n):
                    return True
            for inner in iter_nodes(n):
                if isinstance(inner, dict) and "isvalidsignature" in (member_name(inner) or "").lower():
                    return True
    return False


def _has_asset_sink(func_node):
    """True if the function moves assets / grants authority / makes an arbitrary call - the sink a
    forged-signer attestation would gate in a drain. `staticcall` (the 1271 read) does not count."""
    for call in nodes_of_type(func_node, "FunctionCall"):
        if _callee_member(call) in _ASSET_SINKS:
            return True
    return False


def _has_strict_magic_check(func_node, magic_ids):
    """The function guards authorization on the magic value: a comparison (== / !=) against the
    ERC-1271 magic literal, `...isValidSignature.selector`, or a constant equal to the magic."""
    for op in nodes_of_type(func_node, "BinaryOperation"):
        if op.get("operator") not in ("==", "!="):
            continue
        if _is_magic_operand(op.get("leftExpression") or {}, magic_ids) or _is_magic_operand(op.get("rightExpression") or {}, magic_ids):
            return True
    return False


# ------------------------------- ERC-6492 deploy-and-trust -------------------------------

def _deploys_caller_supplied_factory(func_node):
    """Axis (iii): the function makes a low-level `.call` to, or `create2`-style deploy from, a
    caller-supplied factory address (a parameter / calldata-decoded value). This is the ERC-6492
    counterfactual path Odos mis-inherited: factory + factoryCalldata both come from the signature
    blob, giving an arbitrary call inside signature validation."""
    param_ids = _param_decl_ids(func_node)
    if not param_ids:
        return False
    tainted = param_ids | _local_ids_from_params(func_node, param_ids)
    for call in nodes_of_type(func_node, "FunctionCall"):
        member = _callee_member(call)
        if member in _LOWLEVEL:
            recv = _callee(call).get("expression", {}) or {}
            # factory address caller-controlled AND the payload is caller-controlled
            if _refs_ids(recv, tainted):
                for a in (call.get("arguments") or []):
                    if _refs_ids(a, tainted):
                        return True
    return False


class Erc1271ForgedSigner(Detector):
    rule_id = "R15"
    argument = "drain-erc1271-forged-signer"
    name = "ERC-1271 forged / permissive signer trust"
    help = "authorizes on isValidSignature from an attacker-controlled / permissively-read signer (R15)"

    def detect(self, unit):
        findings = []
        magic_ids = _magic_const_ids(unit)
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue
            for func in contract.functions:
                if func.is_modifier:
                    continue
                fnode = func.node
                trust = _trust_calls(fnode)
                erc6492 = _deploys_caller_supplied_factory(fnode)
                if not trust and not erc6492:
                    continue
                # R15 is a drain rule: axes (i)/(ii) only matter when the attestation gates an
                # asset move. No sink (e.g. Governor.castVoteBySig just records the signer's vote)
                # -> not a drain -> stay silent.
                has_sink = _has_asset_sink(fnode)
                reasons = []
                for _call, signer_expr, kind in trust:
                    if not has_sink:
                        continue
                    if _signer_is_caller_controlled(fnode, signer_expr):
                        reasons.append("signer address is caller-controlled (not immutable / allow-listed)")
                    elif kind in ("direct", "lowlevel") and not _has_strict_magic_check(fnode, magic_ids):
                        reasons.append("isValidSignature result not strictly checked against the ERC-1271 magic value")
                if erc6492 and trust:
                    reasons.append("ERC-6492 path deploys/calls a caller-supplied verifier during validation")
                if not reasons:
                    continue
                # de-dup while keeping order
                seen = set()
                uniq = [r for r in reasons if not (r in seen or seen.add(r))]
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file=contract.source.name,
                        line=func.line,
                        contract=contract.name,
                        function=func.name,
                        message="trusts an ERC-1271 isValidSignature attestation it does not control: "
                        + "; ".join(uniq),
                    )
                )
                break  # one finding per contract is enough
        return findings
