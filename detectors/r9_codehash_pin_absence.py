"""drain-scan R9: trust in external code without a codehash pin.

A wallet that grants standing trust/approval to (or delegates execution to) an external
address whose CODE can change (CREATE2 / metamorphic / swappable-delegate) must pin that
address's code identity (EXTCODEHASH / codehash) and re-verify it before relying on it.
Otherwise the attacker swaps hostile code in at the same address and spends the standing
trust - a metamorphic drain.

Whole-contract reasoning (not syntactic): the defense is a codehash pin usually *computed in
one function and enforced in another* (`trust()` records `pinned[spender]`, `settle()` checks
it). So the detector reasons over the whole contract:

  FIRE  iff the contract OBTAINS a code identity (reads `.codehash`/`extcodehash`, or calls a
        `codeId()`-style getter) but NEVER uses a code-identity-derived value in an `==`/`!=`
        comparison - i.e. it computes a code identity it never enforces (pin missing/dead).

Conservative and 0-FP by construction: a contract that never touches a code identity is never
a candidate (plain bounded-approve / transfer wallets are untouched), and a contract that both
computes AND compares a code identity (a real pin, even across functions) is silent.

Core port (solc AST + core.dataflow name-level taint, no Slither). The original Slither logic
(detectors/r9_codehash_pin_absence.py before the core migration, see git history) used a
SlithIR Binary== scan + a per-contract taint fixpoint; this reproduces it with a contract-level
name taint built from core.dataflow primitives.
"""
from core.detector import Detector, Finding
from core.ast import iter_nodes, node_type, member_name
from core.dataflow import identifiers_read

CODEID_TOKENS = ("codehash", "extcodehash", "codeid")  # matched case-insensitively


def _node_is_codeid(node):
    if not isinstance(node, dict):
        return False
    nt = node.get("nodeType")
    if nt == "MemberAccess" and (member_name(node) or "").lower() in CODEID_TOKENS:
        return True
    if nt == "Identifier" and (node.get("name") or "").lower() in CODEID_TOKENS:
        return True
    return False


def _subtree_has_codeid(node):
    return any(_node_is_codeid(n) for n in iter_nodes(node))


def _contract_assignment_pairs(contract):
    """(lhs_names, rhs_node) for every Assignment and initialized declaration anywhere in the
    contract (across functions) - the substrate for a contract-level name taint."""
    pairs = []
    for n in iter_nodes(contract.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "Assignment":
            pairs.append((identifiers_read(n.get("leftHandSide", {})), n.get("rightHandSide", {})))
        elif nt == "VariableDeclarationStatement" and n.get("initialValue"):
            names = {d.get("name") for d in (n.get("declarations") or []) if d and d.get("name")}
            pairs.append((names, n.get("initialValue")))
    return pairs


def _codeid_taint(contract):
    """Names of variables that hold a code-identity-derived value (seeded from any assignment
    whose RHS references a code identity, then a conservative name-level fixpoint)."""
    pairs = _contract_assignment_pairs(contract)
    tainted = set()
    for lhs_names, rhs in pairs:
        if _subtree_has_codeid(rhs):
            tainted |= {n for n in lhs_names if n}
    changed, passes = True, 0
    while changed and passes < 16:
        changed, passes = False, passes + 1
        for lhs_names, rhs in pairs:
            if identifiers_read(rhs) & tainted:
                for name in lhs_names:
                    if name and name not in tainted:
                        tainted.add(name)
                        changed = True
    return tainted


class CodehashPinAbsence(Detector):
    rule_id = "R9"
    argument = "drain-codehash-pin-absence"
    name = "external-code trust without a codehash pin"
    help = "Computes an external code identity but never enforces it (metamorphic trust, R9)"

    def detect(self, unit):
        findings = []
        for contract in unit.contracts:
            if contract.is_library or contract.is_interface:
                continue

            # (A) is the contract code-identity-aware at all?
            aware_node = next((n for n in iter_nodes(contract.node) if _node_is_codeid(n)), None)
            if aware_node is None:
                continue  # never touches a code identity -> not a candidate (0-FP by design)

            tainted = _codeid_taint(contract)

            # (B) is any code-identity value ENFORCED in an == / != comparison?
            enforced = False
            for n in iter_nodes(contract.node):
                if node_type(n) != "BinaryOperation" or n.get("operator") not in ("==", "!="):
                    continue
                if _subtree_has_codeid(n) or (identifiers_read(n) & tainted):
                    enforced = True
                    break

            if not enforced:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file=contract.source.name,
                        line=contract.source.line_of(aware_node),
                        contract=contract.name,
                        function=None,
                        message="computes an external code identity but never enforces it in a comparison (missing codehash pin)",
                    )
                )
        return findings
