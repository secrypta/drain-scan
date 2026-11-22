"""drain-scan - shared AST helpers for the delegation / calldata cluster (R7, R8, R11).

Own-code analysis over solc's compact AST (no Slither). The cluster's three rules all reduce
to "an external control-transfer whose target and/or data is attacker-supplied, with no
guard", so the guard-recognition and taint plumbing live here once:

  - R7 / R8: a `delegatecall`/`callcode` whose destination is attacker-settable (a parameter,
    or a storage pointer written by an un-gated setter) - delegate-context takeover.
  - R11:     an ordinary `call` forwarding caller-supplied target+data, or a `transferFrom`
    pulling from a caller-supplied `from`, spending a standing approval.

The 0-false-positive requirement is carried by recognizing the defenses the corpus's safe
fixtures actually use and suppressing on them:
  (1) address-allowlist membership check (`mapping(address=>bool)` + revert-on-miss),
  (2) net-effect simulation (snapshot balance/allowance around the call, revert on change),
  (3) governed upgradeable proxy (the logic pointer is written only via a timelock/guardian-
      gated path - R10's domain, safe by delay+veto).

Heuristics are conservative: if a defense is not clearly present the finding is kept. Every
condition is validated by the rule/fixture loop (validate/) against labeled anchors.
"""
from core.ast import iter_nodes, node_type, member_name, call_callee, call_arguments
from core.dataflow import identifiers_read, taint_fixpoint, function_reverts

DELEGATE_MEMBERS = ("delegatecall", "callcode")
CALL_MEMBERS = ("call",)
TRANSFERFROM_MEMBERS = ("transferFrom", "safeTransferFrom")
SNAPSHOT_READS = ("balanceOf", "allowance")
# A function that authorizes the move via an in-call signature/permit is not an arbitrary-callee
# drain (that is R4/R5 territory) - used to keep R11-F2 off legitimate permit routers.
AUTHZ_NAMES = (
    "permit", "permitTransferFrom", "permitWitnessTransferFrom",
    "ecrecover", "isValidSignature", "recover", "tryRecover", "verify",
)
# Token ops that mean "this contract moves tokens" (a standing-approval custody signal for F1).
TOKEN_MOVE_MEMBERS = ("transferFrom", "safeTransferFrom")

# ------------------------------- approve / transferFrom FORM normalizer -------------------------------
# A single real-world drain surface (grant/move ERC-20) is written in two source forms that look
# different in the AST but carry the same operands. The member-only scan (spender=args[0]) was blind
# to the SafeERC20-style STATIC library form, which prepends the token and shifts every operand right
# by one - exactly how the real Hedgey drain (2024-04, ~$44.7M) grants its allowance:
#   member / using-for : token.safeApprove(spender, amount)                 spender=args[0]
#   static library     : SafeERC20.safeApprove(token, spender, amount)      spender=args[1]
# The two forms are told apart by argument count (the wrapper signatures are fixed), so this is
# conservative: plain `approve`/`increaseAllowance` are ERC-20-native (no static wrapper) and stay
# args[0]. Confirmed in real verified code: Hedgey SafeERC20.safeIncreaseAllowance(token,spender,amt),
# Anyswap TransferHelper.safeApprove(token,to,value) / safeTransferFrom(token,from,to,value).

# Allowance-granting members. First arg (member form) or second (static library form) is the spender.
APPROVE_FAMILY_MEMBERS = ("approve", "increaseAllowance", "safeApprove", "forceApprove",
                          "safeIncreaseAllowance")
# Members that carry a leading `token` arg in SafeERC20/TransferHelper static form (so operands
# shift right by one). `approve`/`increaseAllowance` are token-native -> no static wrapper -> no shift.
_STATIC_APPROVE_MEMBERS = ("safeApprove", "forceApprove", "safeIncreaseAllowance")
_STATIC_TRANSFERFROM_MEMBERS = ("safeTransferFrom",)


def approve_spender_amount(member, call):
    """Normalize an approve-family call to (spender_expr, amount_expr) across both source forms.

    Token member form `token.safeApprove(spender, amount)` -> (args[0], args[1]).
    SafeERC20 static library form `SafeERC20.safeApprove(token, spender, amount)` -> (args[1], args[2]).
    The forms are disambiguated by argument count (the safe*/forceApprove wrapper signatures are
    fixed: exactly one extra leading `token` arg in static form). Returns (None, None) when the
    argument shape is not an approve we can read."""
    args = call_arguments(call)
    if member in _STATIC_APPROVE_MEMBERS and len(args) >= 3:
        return args[1], args[2]
    if len(args) >= 2:
        return args[0], args[1]
    return (None, None)


def transferfrom_from(member, call):
    """Normalize a transferFrom/safeTransferFrom call to the `from`-account expression (the account
    whose standing approval is being spent), across both source forms.

    Token member form `token.transferFrom(from, to, amount)` -> args[0].
    SafeERC20 static form `SafeERC20.safeTransferFrom(token, from, to, amount)` -> args[1].
    Disambiguated by argument count (static form prepends `token`). Returns None if unreadable."""
    args = call_arguments(call)
    if member in _STATIC_TRANSFERFROM_MEMBERS and len(args) >= 4:
        return args[1]
    if args:
        return args[0]
    return None


# ------------------------------- call-shape helpers -------------------------------

def _unwrap_options(callee):
    """`addr.call{value: v}(data)` wraps the MemberAccess in a FunctionCallOptions; unwrap it."""
    if node_type(callee) == "FunctionCallOptions":
        return callee.get("expression", {})
    return callee


def member_calls(function, members):
    """(call_node, member, dest_expr) for every FunctionCall in `function` whose callee is a
    MemberAccess `.<member>` with member in `members`. `dest_expr` is the base the member is
    accessed on (the call target / receiver)."""
    out = []
    for call in function.calls():
        callee = _unwrap_options(call_callee(call))
        if node_type(callee) != "MemberAccess":
            continue
        m = member_name(callee)
        if m in members:
            out.append((call, m, callee.get("expression", {})))
    return out


# EVM opcode arg position of the call TARGET: delegatecall(gas, addr, inOff, inLen, outOff, outLen);
# callcode(gas, addr, value, inOff, inLen, outOff, outLen). Target is index 1 in both.
_YUL_TARGET_ARG = 1


def assembly_member_calls(function, members):
    """(yul_call_node, member, dest_names) for every INLINE-ASSEMBLY `delegatecall`/`callcode`
    in `function`. This is the form every real proxy / Safe / ERC-4337 account / Furucombo proxy
    uses - a Yul `delegatecall(gas(), target, ...)` - which `member_calls` (Solidity MemberAccess
    only) is blind to.

    `dest_names` is the set of Solidity variable names the TARGET argument resolves to, and ONLY
    those backed by an `externalReferences` entry (a genuine Solidity-variable reference, not a
    Yul-local such as the `impl` of `let impl := sload(SLOT)`). A target that is a sload / computed
    value / literal resolves to {} and is therefore treated as fixed / in-code (not attacker-
    settable), which keeps ERC-1967-style slot-based proxies silent. Conservative by design: if the
    target is not a direct, externally-bound Yul identifier, no name is produced (0-FP > recall)."""
    out = []
    for n in iter_nodes(function.node):
        if not isinstance(n, dict) or n.get("nodeType") != "InlineAssembly":
            continue
        ext_srcs = {er.get("src") for er in (n.get("externalReferences") or [])}
        yul_ast = n.get("AST")
        if not isinstance(yul_ast, dict):
            continue
        for yn in iter_nodes(yul_ast):
            if not isinstance(yn, dict) or yn.get("nodeType") != "YulFunctionCall":
                continue
            if ((yn.get("functionName") or {}).get("name")) not in members:
                continue
            args = yn.get("arguments") or []
            if len(args) <= _YUL_TARGET_ARG:
                continue
            tgt = args[_YUL_TARGET_ARG]
            dest_names = set()
            if (isinstance(tgt, dict) and tgt.get("nodeType") == "YulIdentifier"
                    and tgt.get("src") in ext_srcs and tgt.get("name")):
                dest_names.add(tgt["name"])
            out.append((yn, (yn.get("functionName") or {}).get("name"), dest_names))
    return out


# ------------------------------- state / guard helpers -------------------------------

def addr_bool_mappings(contract):
    """Names of `mapping(address => bool)` state variables (allowlist candidates)."""
    names = set()
    for sv in contract.state_variables:
        td = (sv.get("typeDescriptions") or {}).get("typeString", "")
        if td.replace(" ", "") == "mapping(address=>bool)" and sv.get("name"):
            names.add(sv["name"])
    return names


def _index_reads(node):
    """(base_name, {key identifier names}) for every IndexAccess under `node`."""
    out = []
    for n in iter_nodes(node):
        if isinstance(n, dict) and n.get("nodeType") == "IndexAccess":
            base = n.get("baseExpression", {})
            if node_type(base) == "Identifier" and base.get("name"):
                out.append((base["name"], identifiers_read(n.get("indexExpression", {}))))
    return out


def reads_allowlist(function, mapping_names, key_name=None):
    """True if `function` indexes one of `mapping_names` (optionally keyed by `key_name`)."""
    for base, keys in _index_reads(function.node):
        if base in mapping_names and (key_name is None or key_name in keys):
            return True
    return False


def writers_of(contract, var_name):
    """Non-constructor functions that assign to state variable `var_name` (plain Identifier
    LHS, i.e. `var = ...`)."""
    out = []
    for f in contract.functions:
        if f.is_constructor or f.is_modifier:
            continue
        for n in iter_nodes(f.node):
            if isinstance(n, dict) and n.get("nodeType") == "Assignment":
                lhs = n.get("leftHandSide", {})
                if node_type(lhs) == "Identifier" and lhs.get("name") == var_name:
                    out.append(f)
                    break
    return out


def is_allowlist_guarded(contract, function, dest_ids, dest_state_vars):
    """The call destination is constrained by an address-allowlist membership check + revert.

    Parameter/local destination: an in-function membership check keyed by a destination
    identifier, with a revert. Storage destination: every non-constructor writer gates
    membership + reverts (the pointer is only as safe as the setters that write it)."""
    maps = addr_bool_mappings(contract)
    if not maps:
        return False
    if not dest_state_vars:
        keyed = any(reads_allowlist(function, maps, key_name=k) for k in dest_ids)
        return keyed and function_reverts(function)
    for var in dest_state_vars:
        writers = writers_of(contract, var)
        if not writers:
            return False
        if not all(reads_allowlist(w, maps) and function_reverts(w) for w in writers):
            return False
    return True


def _has_timelock_or_guardian_gate(function):
    """The function is gated by a timelock (reads block.timestamp/number) or a guardian/veto
    key check (and can revert) - the R10 governed-upgrade shape."""
    for n in iter_nodes(function.node):
        if isinstance(n, dict) and n.get("nodeType") == "MemberAccess" and member_name(n) in ("timestamp", "number"):
            base = n.get("expression", {})
            if node_type(base) == "Identifier" and base.get("name") == "block":
                return True
    ids = identifiers_read(function.node)
    if any(g in ids for g in ("guardian", "guard", "veto")) and function_reverts(function):
        return True
    return False


def is_governed_proxy_write(contract, dest_state_vars):
    """The destination storage pointer is written ONLY through timelock/guardian-gated
    functions (a governed upgradeable proxy - R10's domain, safe by delay+veto)."""
    if not dest_state_vars:
        return False
    for var in dest_state_vars:
        writers = writers_of(contract, var)
        if not writers:
            return False  # no non-ctor writer at all -> not a mutable-governed pointer here
        if not all(_has_timelock_or_guardian_gate(w) for w in writers):
            return False
    return True


def simulates_net_effect(contract):
    """The contract snapshots an ERC-20 balance/allowance before a delegate/low-level call and
    re-reads one after, and can revert - the net-effect-simulation defense (the drain is rolled
    back). Measured contract-wide because the reference impl splits snapshot/commit across two
    functions."""
    before = after = False
    for f in contract.functions:
        seen_forward = False
        for n in iter_nodes(f.node):
            if not isinstance(n, dict) or n.get("nodeType") != "FunctionCall":
                continue
            callee = _unwrap_options(n.get("expression", {}))
            if node_type(callee) != "MemberAccess":
                continue
            m = member_name(callee)
            if m in DELEGATE_MEMBERS or m in CALL_MEMBERS:
                seen_forward = True
            elif m in SNAPSHOT_READS:
                if seen_forward:
                    after = True
                else:
                    before = True
    if not (before and after):
        return False
    return any(function_reverts(f) for f in contract.functions)


# ------------------------------- shared detection bodies -------------------------------

def delegate_hijack_findings(unit, make_finding):
    """Core detection shared by R7 and R8: a delegatecall/callcode whose destination is
    attacker-settable and is not allowlist-guarded, net-effect-simulated, or a governed proxy.

    `make_finding(contract, function, call)` builds the rule-specific Finding."""
    findings = []
    for contract in unit.contracts:
        if contract.is_interface or contract.is_library:
            continue
        if simulates_net_effect(contract):
            continue
        svars = set(contract.state_variable_names())
        for function in contract.functions:
            if function.is_modifier:
                continue
            tainted = taint_fixpoint(function, set(function.parameter_names))
            for call, _m, dest in member_calls(function, DELEGATE_MEMBERS):
                dest_ids = identifiers_read(dest)
                dest_from_param = bool(dest_ids & tainted)
                dest_state_vars = dest_ids & svars
                if not (dest_from_param or dest_state_vars):
                    continue  # fixed / immutable / in-code destination - not attacker-settable
                if is_allowlist_guarded(contract, function, dest_ids, dest_state_vars):
                    continue
                if dest_state_vars and is_governed_proxy_write(contract, dest_state_vars):
                    continue
                if delegatecall_result_must_revert(function, call):
                    continue  # success is required to be false -> tx reverts, no state persists
                findings.append(make_finding(contract, function, call))
            # Inline-assembly (Yul) delegatecall - the form every real proxy / Safe / ERC-4337
            # account uses. Same attacker-settable-target discriminator, plus one extra 0-FP guard:
            # a caller-gated delegate-execute (Solady ERC4337.delegateExecute `onlyEntryPointOrOwner`)
            # is a trusted-owner AA primitive, not an open hijack, so an access-controlled function
            # is suppressed on this (assembly) path. The high-level path above is left unchanged.
            for ycall, _ym, dest_names in assembly_member_calls(function, DELEGATE_MEMBERS):
                dest_param_names = dest_names & tainted
                dest_from_param = bool(dest_param_names) and _asm_target_attacker_controlled(
                    contract, function, dest_param_names)
                dest_state_vars = dest_names & svars
                if not (dest_from_param or dest_state_vars):
                    continue  # slot/computed/getter-bound/in-code target - not attacker-settable
                if is_allowlist_guarded(contract, function, dest_names, dest_state_vars):
                    continue
                if dest_state_vars and is_governed_proxy_write(contract, dest_state_vars):
                    continue
                if _is_access_guarded(function):
                    continue  # caller-gated delegate-execute (trusted-owner AA primitive)
                findings.append(make_finding(contract, function, ycall))
    return findings


def delegatecall_result_must_revert(function, call):
    """True if `call` (a delegatecall) binds a success flag that the function then REQUIRES to be
    FALSE - `require(!ok)` or `if (ok) revert` - so a *successful* delegatecall reverts the whole
    transaction and can never persist state. This is the SWC-112 documented "mandatory-revert"
    pattern (`require(!_to.delegatecall(_data))`): genuinely not a hijack, so it is suppressed.
    Scoped to THIS delegatecall's own success variable, so a real hijack (which needs the call to
    succeed and persist - `require(ok)` or an ignored result) is unaffected. 0-FP > recall."""
    call_id = call.get("id")
    success_name = None
    for n in iter_nodes(function.node):
        if not isinstance(n, dict) or n.get("nodeType") != "VariableDeclarationStatement":
            continue
        if (n.get("initialValue") or {}).get("id") == call_id:
            decls = n.get("declarations") or []
            if decls and isinstance(decls[0], dict):
                success_name = decls[0].get("name")
            break
    if not success_name:
        return False
    for n in iter_nodes(function.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "FunctionCall":
            callee = call_callee(n)
            if node_type(callee) == "Identifier" and callee.get("name") == "require":
                args = call_arguments(n)
                if (args and node_type(args[0]) == "UnaryOperation"
                        and args[0].get("operator") == "!"
                        and node_type(args[0].get("subExpression", {})) == "Identifier"
                        and args[0].get("subExpression", {}).get("name") == success_name):
                    return True
        elif nt == "IfStatement":
            cond = n.get("condition", {})
            if node_type(cond) == "Identifier" and cond.get("name") == success_name:
                for b in iter_nodes(n.get("trueBody", {})):
                    if not isinstance(b, dict):
                        continue
                    if b.get("nodeType") == "RevertStatement":
                        return True
                    if b.get("nodeType") == "FunctionCall":
                        c = call_callee(b)
                        if node_type(c) == "Identifier" and c.get("name") == "revert":
                            return True
    return False


def function_authorizes(function):
    """True if the function itself consumes a permit / verifies a signature authorizing the
    move (so it is not an arbitrary-callee drain - R4/R5 own that)."""
    for call in function.calls():
        callee = _unwrap_options(call_callee(call))
        name = None
        if node_type(callee) == "MemberAccess":
            name = member_name(callee)
        elif node_type(callee) == "Identifier":
            name = callee.get("name")
        if name in AUTHZ_NAMES:
            return True
    return False


def _expr_mentions_sender(node):
    """True if the subtree `node` contains msg.sender / _msgSender() / msgSender() anywhere."""
    for n in iter_nodes(node):
        if isinstance(n, dict) and expr_is_msg_sender(n):
            return True
    return False


def _authorizes_caller(function):
    """A GENUINE caller-authorization check on msg.sender/_msgSender() - the caller identity is
    tested inside a `require`/`assert`, or inside an `if (...) { revert }` guard clause. This is
    the discriminator requested by the F2 audit note: a bare *mention* of msg.sender (logging
    `emit X(msg.sender)`, an assignment `address a = msg.sender`, a refund `msg.sender.transfer`)
    is NOT a caller gate and must not suppress the finding. Mirrors the enforcement-not-presence
    style of R13-F1 `_asserts_zero_residual` / `delegatecall_result_must_revert`.

    Being inside a require/assert/if-revert condition IS the authorization signal, so any form of
    msg.sender test there counts: `== owner` / `!= owner`, mapping membership
    `require(isOwner[msg.sender])`, or a predicate call `require(_isAuthorized(msg.sender))`."""
    for n in iter_nodes(function.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "FunctionCall":
            callee = call_callee(n)
            if (node_type(callee) == "Identifier" and callee.get("name") in ("require", "assert")):
                args = call_arguments(n)
                if args and _expr_mentions_sender(args[0]):
                    return True
        elif nt == "IfStatement":
            if _expr_mentions_sender(n.get("condition", {})) and _branch_reverts(n.get("trueBody", {})):
                return True
    return False


def _branch_reverts(body):
    """True if the statement/block `body` can revert - a RevertStatement, a `revert(...)` /
    `require(false, ..)` call. Used to recognize an `if (badCaller) { revert }` guard clause."""
    for b in iter_nodes(body):
        if not isinstance(b, dict):
            continue
        if b.get("nodeType") == "RevertStatement":
            return True
        if b.get("nodeType") == "FunctionCall":
            c = call_callee(b)
            if node_type(c) == "Identifier" and c.get("name") in ("revert", "require"):
                return True
    return False


def _is_access_guarded(function):
    """The function is gated against arbitrary callers: an access-control/role/ownership modifier,
    a genuine in-body caller-authorization check (msg.sender tested in a require/assert/if-revert -
    see `_authorizes_caller`; a bare mention is NOT a gate), a role check (hasRole/_checkRole), or
    a timelock/guardian gate. A `require(ok, ...)` on a call's return value is NOT a guard (it
    checks the callee, not the caller) - so an open multicall like Squid.run is correctly seen as
    un-guarded."""
    for mod in function.node.get("modifiers", []) or []:
        nm = ((mod.get("modifierName") or {}).get("name") or "").lower()
        if nm.startswith("only") or "role" in nm or "owner" in nm or "auth" in nm or "guard" in nm:
            return True
    if _has_timelock_or_guardian_gate(function):
        return True
    if _authorizes_caller(function):
        return True
    for n in iter_nodes(function.node):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "FunctionCall":
            c = _unwrap_options(n.get("expression", {}))
            nm = member_name(c) if node_type(c) == "MemberAccess" else (
                c.get("name") if node_type(c) == "Identifier" else None)
            if nm in ("hasRole", "checkRole", "_checkRole", "_checkOwner"):
                return True
    return False


def _internal_callers(contract, func_name):
    """Same-contract functions that call `func_name` as an internal call (`func_name(...)`)."""
    out = []
    for f in contract.functions:
        for call in f.calls():
            callee = call_callee(call)
            if node_type(callee) == "Identifier" and callee.get("name") == func_name:
                out.append(f)
                break
    return out


def f1_reachable_unguarded(contract, function):
    """True if `function`'s arbitrary call is reachable from an UN-access-controlled entry point
    (so an arbitrary caller can trigger it - the R11-F1 defect). An external/public function is
    judged directly; an internal/private helper (e.g. OZ TimelockController._execute) is judged
    by its direct public callers - if every public caller is access/role/timelock-guarded, the
    arbitrary call is governance-gated and NOT an FP. 0-FP > recall: when reachability is unclear
    (no public caller found, deeper chains), suppress."""
    if function.visibility in ("external", "public"):
        return not _is_access_guarded(function)
    public_callers = [c for c in _internal_callers(contract, function.name)
                      if c.visibility in ("external", "public")]
    if not public_callers:
        return False
    return any(not _is_access_guarded(c) for c in public_callers)


def _is_token_pull_name(name):
    """A transfer member/helper that pulls third-party tokens: the direct member form
    (`transferFrom` / `safeTransferFrom`) or a library-helper form (`transferTokens`)."""
    name = (name or "").lower()
    return "transfer" in name and ("from" in name or "token" in name)


def contract_has_approval_custody(contract):
    """Variant-B custody signal for F1: the contract itself demonstrably moves third-party
    tokens or maintains an allowance it debits. A pure arbitrary executor that holds no approvals
    of its own (OZ TimelockController, a bare multicall like Squid) has NO such signal, so F1 does
    not fire on it - only a contract that actually spends a standing approval via an arbitrary call
    is in scope.

    Token-move recognized in two forms (the member-only form was blind to the real Hedgey, whose
    deposit is pulled through its own TransferHelper library, not a direct transferFrom member -
    the custody counterpart of the SafeERC20 static-form approve blindness):
      (1) a direct `transferFrom` / `safeTransferFrom` member call;
      (2) a library-helper pull that lands tokens in `address(this)` - a transfer member/helper
          (`TransferHelper.transferTokens(token, from, address(this), amount)`, which internally
          does `SafeERC20.safeTransferFrom`) with `address(this)` passed as an argument. The
          `address(this)`-destination requirement keeps a stateless forwarder (no self-custody)
          out of scope, so this is additive precision, not a widening of what counts as custody."""
    for sv in contract.state_variables:
        if "allow" in (sv.get("name") or "").lower():
            return True
    for function in contract.functions:
        for call in function.calls():
            callee = _unwrap_options(call_callee(call))
            if node_type(callee) != "MemberAccess":
                continue
            name = member_name(callee)
            if name in TOKEN_MOVE_MEMBERS:
                return True
            if _is_token_pull_name(name) and any(
                is_address_this(a) for a in call_arguments(call)
            ):
                return True
    return False


def transfer_is_authorized(function):
    """F2 suppressor: the transfer is authorized, so it is not an arbitrary-callee drain.
    Authorization = a signature/permit check (permit / ecrecover / isValidSignature / .verify,
    or signature/nonce/deadline markers with a revert), OR allowance accounting (the function
    debits an `allowance`-style balance and reverts on insufficiency, e.g. Permit2
    AllowanceTransfer._transfer / an ERC-20's own transferFrom). Keeps R11-F2 off legitimate
    transfer proxies while still firing on an un-authorized drain (DrainerKit.drain)."""
    if function_authorizes(function):
        return True
    ids = {i.lower() for i in identifiers_read(function.node)}
    if function_reverts(function) and (
        {"signature", "nonce", "deadline"} & ids or any("allow" in i for i in ids)
    ):
        return True
    return False


def msg_sender_bound(function, names):
    """True if the function requires `msg.sender == <name>` (or the reverse) for any name in
    `names` - the caller is bound to the token owner, so the pull is authorized, not arbitrary."""
    want = set(names)
    for n in iter_nodes(function.node):
        if not isinstance(n, dict) or n.get("nodeType") != "BinaryOperation" or n.get("operator") != "==":
            continue
        sides = [n.get("leftExpression", {}), n.get("rightExpression", {})]
        has_sender = any(
            node_type(s) == "MemberAccess" and member_name(s) == "sender"
            and node_type(s.get("expression", {})) == "Identifier"
            and s.get("expression", {}).get("name") == "msg"
            for s in sides
        )
        has_name = any(node_type(s) == "Identifier" and s.get("name") in want for s in sides)
        if has_sender and has_name:
            return True
    return False


def expr_is_msg_sender(expr):
    """True if `expr` is `msg.sender` or an OZ-style `_msgSender()` / `msgSender()` call - i.e. it
    resolves to the transaction's immediate caller."""
    if not isinstance(expr, dict):
        return False
    if (node_type(expr) == "MemberAccess" and member_name(expr) == "sender"
            and node_type(expr.get("expression", {})) == "Identifier"
            and expr.get("expression", {}).get("name") == "msg"):
        return True
    if node_type(expr) == "FunctionCall":
        callee = call_callee(expr)
        if node_type(callee) == "Identifier" and callee.get("name") in ("_msgSender", "msgSender"):
            return True
    return False


def is_address_this(expr):
    """True if `expr` is the literal `address(this)` - funds forwarded here STAY in the contract
    (a self-deposit sink), not sent out to an attacker-chosen beneficiary."""
    if not isinstance(expr, dict) or node_type(expr) != "FunctionCall" or expr.get("kind") != "typeConversion":
        return False
    tn = expr.get("expression", {})
    if node_type(tn) != "ElementaryTypeNameExpression":
        return False
    name = tn.get("typeName")
    name = name.get("name") if isinstance(name, dict) else name
    if name != "address":
        return False
    args = expr.get("arguments", []) or []
    return len(args) == 1 and node_type(args[0]) == "Identifier" and args[0].get("name") == "this"


def _asm_target_attacker_controlled(contract, function, dest_param_names):
    """For the inline-assembly delegate path: is the delegatecall TARGET, which is a parameter of
    `function`, actually attacker/calldata-controlled?

    An external/public function takes its parameter straight from calldata -> yes. An internal/
    private helper's parameter is only as dangerous as what its callers pass: it is attacker-
    controlled iff some same-contract caller forwards one of ITS OWN parameters into that argument
    position (calldata flows through). A target bound at the call site to an internal getter
    (OpenZeppelin `Proxy._delegate(_implementation())`, whose implementation is the governed slot)
    or to a state read is NOT attacker-controlled. Mirrors `from_bound_to_sender` /
    `f1_reachable_unguarded`; conservative - an unresolved internal target does not fire (0-FP >
    recall)."""
    if function.visibility in ("external", "public"):
        return True
    for name in dest_param_names:
        idx = _param_index(function, name)
        if idx is None:
            continue
        for caller in _internal_callers(contract, function.name):
            caller_params = set(caller.parameter_names)
            for call in caller.calls():
                callee = call_callee(call)
                if node_type(callee) == "Identifier" and callee.get("name") == function.name:
                    args = call_arguments(call)
                    if idx < len(args) and (identifiers_read(args[idx]) & caller_params):
                        return True
    return False


def _param_index(function, name):
    params = (function.node.get("parameters") or {}).get("parameters", []) or []
    for i, p in enumerate(params):
        if p.get("name") == name:
            return i
    return None


def from_bound_to_sender(contract, function, from_name):
    """True if the transferFrom `from`-account is bound to msg.sender - directly (`require(msg.sender
    == from)`) OR, for an INTERNAL/private forwarder, at every same-contract call site (e.g. OZ/Solady
    ERC4626 `deposit() -> _deposit(_msgSender(), ...)`). The caller is spending their OWN approval, so
    it is a self-pull, not a third party's standing approval being drained. Mirrors the interprocedural
    reachability judgement in `f1_reachable_unguarded`; conservative - unclear callers do NOT suppress."""
    if msg_sender_bound(function, [from_name]):
        return True
    if function.visibility not in ("internal", "private"):
        return False
    idx = _param_index(function, from_name)
    if idx is None:
        return False
    sites = []
    for caller in _internal_callers(contract, function.name):
        for call in caller.calls():
            callee = call_callee(call)
            if node_type(callee) == "Identifier" and callee.get("name") == function.name:
                args = call_arguments(call)
                sites.append(args[idx] if idx < len(args) else {})
    return bool(sites) and all(expr_is_msg_sender(a) for a in sites)
