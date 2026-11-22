"""drain-scan R14: reentrancy / CEI-violation approval-reuse drain.

Flags a function that, with no reentrancy guard, makes an external call capable of re-entering
(an ERC-721/1155 `safe*` transfer that fires a receiver hook, or a low-level `.call`) and THEN
- after that call - pulls assets with `transferFrom`/`safeTransferFrom` whose **source party**
(the `from` argument) is read from storage that *another* externally-reachable function can
mutate. An attacker re-enters during the callback, redirects that storage (the pulled-from
party) to a victim holding a standing operator approval, and the post-callback pull drains the
victim. This is a check-effects-interactions (CEI) violation: the party the pull trusts is
re-read from mutable storage *after* the external call instead of being cached before it.

This is the root cause behind the NFTTrader.org swap drain (2023-12-16, ~$3M): `closeSwapIntent`
returns the escrowed NFT with a `safeTransferFrom` (callback), then pulls the counterparty's NFT
reading `swap.counterPart` from storage - and `editCounterPart` (a separate external function,
no reentrancy guard) can be re-entered mid-callback to set the victim as counterparty.

Predicate (all must hold for a function F in a `contract` C - interfaces/libraries skipped):

  1. Externally reachable   - F.visibility in {public, external}, not a constructor/modifier.
  2. No reentrancy guard     - F carries no modifier whose name denotes a reentrancy lock
                               (`nonReentrant`, `...reentran...`, `...lock...`/`mutex`). Any such
                               modifier suppresses F entirely (0-FP > recall).
  3. Reentry point E         - F contains an external call that can re-enter: a member call whose
                               memberName is a receiver-firing `safe*` transfer
                               (safeTransferFrom / safeBatchTransferFrom / safeMint), or a
                               low-level `.call` / `sendValue`.
  4. Post-callback victim pull T - AFTER E (strictly later by source offset) F contains a
                               `transferFrom` / `safeTransferFrom` whose **first argument** (the
                               `from` / source party) reads a state variable of C - directly, or
                               through a `storage`-reference local bound to one - that is written
                               by some *other* externally-reachable function G != F of C.

(4) is the discriminator against the legal callbacks that live in every OZ/Solady ERC-721/1155:
a CEI-correct settlement caches the counterparty/terms in locals *before* the external call, so
the pull's `from` argument is a local, not externally-mutable storage, and the predicate does
not fire. A plain `safeTransferFrom` (no second pull after a reentry point) does not fire. The
externally-mutable-source requirement - the pulled-from party can be redirected by a *different*
entrypoint between E and T - is exactly the reentrancy-redirect surface, and is absent from a
correct callback. Conservative by design: the guard check, the "other external writer" gate and
the strict ordering each only shrink what fires, trading recall for zero false positives.

Engine: the drain-scan analysis core (solc AST, no Slither). Subclasses core.detector.Detector
and reads the AST through core.ast helpers only, exactly like detectors/r12_*.py.
"""
from core.detector import Detector, Finding
from core.ast import (
    node_type,
    member_name,
    call_callee,
    call_arguments,
    iter_nodes,
    nodes_of_type,
)

# External calls that can hand control back to an attacker mid-execution.
REENTRY_HOOKS = ("safeTransferFrom", "safeBatchTransferFrom", "safeMint", "sendValue")
LOWLEVEL_CALL = ("call",)  # `addr.call{...}(...)` / `addr.call(...)`
# Value-moving pulls whose `from` (first arg) names the drained party.
PULL_MEMBERS = ("transferFrom", "safeTransferFrom", "safeBatchTransferFrom")
# A modifier whose name contains any of these is treated as a reentrancy lock.
GUARD_HINTS = ("reentran", "nonreentrant", "mutex")


def _src_offset(node):
    """Start byte-offset from a node's `src` ('offset:len:fileIdx'), or -1."""
    if not isinstance(node, dict):
        return -1
    src = node.get("src")
    if not src:
        return -1
    try:
        return int(src.split(":")[0])
    except (ValueError, IndexError):
        return -1


def _identifier_names(root):
    """Every Identifier `name` anywhere under `root`."""
    return {
        n.get("name")
        for n in iter_nodes(root)
        if isinstance(n, dict) and n.get("nodeType") == "Identifier" and n.get("name")
    }


def _callee_member(call):
    """memberName of a FunctionCall's callee when it is a MemberAccess, stripping any
    FunctionCallOptions wrapper (`addr.call{value: v}(...)`), else None."""
    callee = call_callee(call)
    if node_type(callee) == "FunctionCallOptions":
        callee = callee.get("expression", {})
    if node_type(callee) == "MemberAccess":
        return member_name(callee)
    return None


def _is_reentry_call(call):
    m = _callee_member(call)
    return m in REENTRY_HOOKS or m in LOWLEVEL_CALL


def _has_reentrancy_guard(function):
    """P2: F carries a modifier whose name denotes a reentrancy lock."""
    for m in function.node.get("modifiers") or []:
        if not isinstance(m, dict) or m.get("nodeType") != "ModifierInvocation":
            continue
        name = ((m.get("modifierName") or {}).get("name") or "").lower()
        if any(h in name for h in GUARD_HINTS) or name.endswith("lock"):
            return True
    return False


def _storage_ref_locals(function, state_var_names):
    """Map local name -> set(state var names it aliases) for `T storage l = <state...>;`
    declarations in F. These let `l.field` be recognised as a read of its backing state var."""
    svs = set(state_var_names)
    aliases = {}
    for vds in nodes_of_type(function.node, "VariableDeclarationStatement"):
        decls = vds.get("declarations") or []
        init = vds.get("initialValue")
        if init is None:
            continue
        for d in decls:
            if not isinstance(d, dict) or d.get("storageLocation") != "storage":
                continue
            name = d.get("name")
            backing = _identifier_names(init) & svs
            if name and backing:
                aliases[name] = backing
    return aliases


def _reads_external_storage(arg, ext_written, storage_aliases):
    """True if `arg` reads a state var in `ext_written` directly, or via a storage-ref local
    bound to such a state var."""
    names = _identifier_names(arg)
    if names & ext_written:
        return True
    for local, backing in storage_aliases.items():
        if local in names and (backing & ext_written):
            return True
    return False


class ReentrantApprovalReuse(Detector):
    rule_id = "R14"
    argument = "drain-reentrant-approval-reuse"
    name = "reentrancy / CEI approval-reuse drain"
    help = "External call then a victim pull whose source is externally-mutable post-callback (R14)"

    def _external_writers_other_than(self, contract, state_var_names):
        """Per state var, whether SOME public/external function of C writes it. Returns, for each
        function, the set of state vars written by a *different* external function (computed once
        per contract and filtered per F by the caller)."""
        svs = set(state_var_names)
        written_by = {}  # function node id() -> set(state vars it writes)
        ext_funcs = []
        for fn in contract.functions:
            if fn.is_modifier or fn.is_constructor:
                continue
            if fn.visibility not in ("public", "external"):
                continue
            w = set()
            for asn in fn.assignments():
                w |= _identifier_names(asn.get("leftHandSide", {})) & svs
            written_by[id(fn.node)] = w
            ext_funcs.append(fn)
        return written_by

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_interface or contract.is_library:
                continue
            state_vars = contract.state_variable_names()
            if not state_vars:
                continue
            written_by = self._external_writers_other_than(contract, state_vars)

            for function in contract.functions:
                if function.is_constructor or function.is_modifier:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if _has_reentrancy_guard(function):       # P2
                    continue

                # State vars an external function OTHER than F can mutate (redirect surface).
                ext_written = set()
                for fnode_id, w in written_by.items():
                    if fnode_id != id(function.node):
                        ext_written |= w
                if not ext_written:
                    continue

                calls = function.calls()
                reentry_offsets = [
                    _src_offset(c) for c in calls if _is_reentry_call(c)
                ]
                reentry_offsets = [o for o in reentry_offsets if o >= 0]
                if not reentry_offsets:                   # P3: no reentry point
                    continue
                first_reentry = min(reentry_offsets)

                storage_aliases = _storage_ref_locals(function, state_vars)

                flagged = None
                for call in calls:
                    if _callee_member(call) not in PULL_MEMBERS:
                        continue
                    if _src_offset(call) <= first_reentry:   # must be AFTER the reentry point
                        continue
                    args = call_arguments(call)
                    if not args:
                        continue
                    if _reads_external_storage(args[0], ext_written, storage_aliases):  # P4
                        flagged = call
                        break
                if flagged is None:
                    continue

                line = contract.source.line_of(flagged) or function.line
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file=contract.source.name,
                        line=line,
                        contract=contract.name,
                        function=function.name,
                        message=(
                            "pulls assets with transferFrom after a re-entrant external call, "
                            "reading the source party from storage that another external function "
                            "can mutate - a mid-callback redirect drains a standing approval "
                            "(CEI violation; no reentrancy guard)"
                        ),
                    )
                )
        return findings
