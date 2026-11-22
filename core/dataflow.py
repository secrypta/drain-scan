"""drain-scan core.dataflow - light, name-level taint / reachability over the AST.

Our replacement for the parts of SlithIR the rule clusters actually use. It is deliberately
small and AST-level (variable *names*, not SSA): a conservative fixpoint that answers "does a
value derived from these seeds reach here?", which is what R4 (permit arg -> transferFrom
amount), R8 (calldata target -> delegatecall destination) and R9 (code-identity -> enforced
comparison) need. It grows as those rules are ported; today it offers the primitives below.

Name-level means it can over-approximate across same-named locals in different scopes; the
rules that use it pair it with a structural check (the detector decides), exactly as the
Slither-era rules paired SlithIR taint with a guard recognizer. Honest about its limits: it
is a heuristic base, validated by the rule/fixture loop, not a full dataflow engine.
"""
from core.ast import iter_nodes, node_type


def identifiers_read(node):
    """Names of every Identifier appearing anywhere under `node`."""
    names = set()
    for n in iter_nodes(node):
        if isinstance(n, dict) and n.get("nodeType") == "Identifier" and n.get("name"):
            names.add(n["name"])
    return names


def assignment_pairs(function):
    """(lhs_names, rhs_node) for each Assignment and each initialized VariableDeclaration
    inside `function`. Used to propagate taint by variable name."""
    pairs = []
    for n in iter_nodes(function.node):
        if not isinstance(n, dict):
            continue
        nt = n.get("nodeType")
        if nt == "Assignment":
            lhs = n.get("leftHandSide", {})
            rhs = n.get("rightHandSide", {})
            pairs.append((identifiers_read(lhs), rhs))
        elif nt == "VariableDeclarationStatement" and n.get("initialValue"):
            decls = n.get("declarations") or []
            names = {d.get("name") for d in decls if d and d.get("name")}
            pairs.append((names, n.get("initialValue")))
    return pairs


def taint_fixpoint(function, seeds):
    """Set of variable names in `function` tainted from `seeds` (a set of names), following
    assignments / declarations transitively. Conservative name-level fixpoint."""
    tainted = set(seeds)
    pairs = assignment_pairs(function)
    changed = True
    passes = 0
    while changed and passes < 16:
        changed = False
        passes += 1
        for lhs_names, rhs in pairs:
            if identifiers_read(rhs) & tainted:
                for name in lhs_names:
                    if name and name not in tainted:
                        tainted.add(name)
                        changed = True
    return tainted


def call_args_touch(call, names):
    """True if any argument of a FunctionCall node reads one of `names`."""
    from core.ast import call_arguments
    for arg in call_arguments(call):
        if identifiers_read(arg) & names:
            return True
    return False


def function_reverts(function):
    """True if the function can revert (require/assert/revert or a revert statement)."""
    for n in iter_nodes(function.node):
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "RevertStatement":
            return True
        if n.get("nodeType") == "FunctionCall":
            callee = n.get("expression", {})
            if node_type(callee) == "Identifier" and callee.get("name") in ("require", "assert", "revert"):
                return True
    return False
