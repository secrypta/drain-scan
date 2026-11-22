"""drain-scan core.ast - navigate solc's AST without touching raw JSON in the detectors.

solc's compact AST is plain nested dicts keyed by `nodeType`. This module wraps the parts a
detector reasons about - sources, contracts, functions - and offers small, explicit helpers
to walk expression nodes (FunctionCall, MemberAccess, Assignment, Identifier, Literal, ...),
so a rule reads as intent, not JSON spelunking.

A node is still a dict (kept deliberately thin); the helpers below are how detectors touch
it. Line numbers come from the `src` field ("byteOffset:length:fileIndex") resolved against
the owning source file's bytes.
"""
import os


# ------------------------------- node helpers -------------------------------

def node_type(node):
    return node.get("nodeType") if isinstance(node, dict) else None


def member_name(node):
    """memberName of a MemberAccess node (e.g. `.approve`, `.max`), else None."""
    return node.get("memberName") if isinstance(node, dict) else None


def iter_nodes(node):
    """Yield `node` and every descendant dict node (depth-first)."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from iter_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from iter_nodes(value)


def nodes_of_type(root, *types):
    """All dict nodes under `root` whose nodeType is one of `types`."""
    want = set(types)
    return [n for n in iter_nodes(root) if isinstance(n, dict) and n.get("nodeType") in want]


def call_callee(call):
    """The `expression` (callee) of a FunctionCall node."""
    return call.get("expression", {}) if isinstance(call, dict) else {}


def call_arguments(call):
    """The argument nodes of a FunctionCall node (list)."""
    return call.get("arguments", []) if isinstance(call, dict) else []


def identifier_name(node):
    """Name of an Identifier node (e.g. the `block` in `block.timestamp`), else None.
    Callers that have a MemberAccess pass its `.expression` (the base) in explicitly."""
    if not isinstance(node, dict):
        return None
    if node.get("nodeType") == "Identifier":
        return node.get("name")
    return None


# ------------------------------- wrappers -------------------------------

class SourceFile:
    """One compiled source: its SourceUnit AST plus the bytes (for line resolution)."""

    def __init__(self, name, index, ast):
        self.name = name
        self.index = index
        self.ast = ast
        self._text = None

    @property
    def text(self):
        if self._text is None:
            try:
                with open(self.name, "rb") as fh:
                    self._text = fh.read()
            except OSError:
                self._text = b""
        return self._text

    def line_of(self, node):
        """1-indexed line of a node from its `src` ('offset:len:fileIdx'), or None."""
        if not isinstance(node, dict):
            return None
        src = node.get("src")
        if not src:
            return None
        try:
            offset = int(src.split(":")[0])
        except (ValueError, IndexError):
            return None
        text = self.text
        if not text:
            return None
        return text[:offset].count(b"\n") + 1

    @property
    def basename(self):
        return os.path.basename(self.name)


class Function:
    """A FunctionDefinition / ModifierDefinition inside a contract."""

    def __init__(self, node, contract):
        self.node = node
        self.contract = contract

    @property
    def kind(self):
        # "function" | "constructor" | "fallback" | "receive" | (modifier -> None)
        return self.node.get("kind")

    @property
    def is_constructor(self):
        return self.node.get("kind") == "constructor"

    @property
    def is_modifier(self):
        return self.node.get("nodeType") == "ModifierDefinition"

    @property
    def name(self):
        n = self.node.get("name")
        if n:
            return n
        return self.kind or "<anonymous>"

    @property
    def visibility(self):
        return self.node.get("visibility")

    @property
    def parameter_names(self):
        params = (self.node.get("parameters") or {}).get("parameters", []) or []
        return [p.get("name") for p in params if p.get("name")]

    def walk(self):
        return iter_nodes(self.node)

    def calls(self):
        """FunctionCall nodes in this function's body/modifiers."""
        return nodes_of_type(self.node, "FunctionCall")

    def assignments(self):
        return nodes_of_type(self.node, "Assignment")

    @property
    def line(self):
        return self.contract.source.line_of(self.node)


class Contract:
    """A ContractDefinition (contract / library / interface)."""

    def __init__(self, node, source):
        self.node = node
        self.source = source

    @property
    def name(self):
        return self.node.get("name")

    @property
    def kind(self):
        return self.node.get("contractKind")  # "contract" | "library" | "interface"

    @property
    def is_library(self):
        return self.kind == "library"

    @property
    def is_interface(self):
        return self.kind == "interface"

    @property
    def is_abstract(self):
        return bool(self.node.get("abstract"))

    @property
    def functions(self):
        return [
            Function(n, self)
            for n in self.node.get("nodes", [])
            if node_type(n) in ("FunctionDefinition", "ModifierDefinition")
        ]

    @property
    def state_variables(self):
        return [
            n
            for n in self.node.get("nodes", [])
            if node_type(n) == "VariableDeclaration" and n.get("stateVariable")
        ]

    def state_variable_names(self):
        return [n.get("name") for n in self.state_variables if n.get("name")]

    def walk(self):
        return iter_nodes(self.node)

    @property
    def line(self):
        return self.source.line_of(self.node)


class Unit:
    """A compiled unit: every source and the contracts across them."""

    def __init__(self, sources):
        self.sources = sources  # list[SourceFile]

    @classmethod
    def from_compile(cls, data):
        """Build a Unit from core.compile.compile_source() output (combined-json)."""
        source_list = data.get("sourceList")
        src_map = data.get("sources", {})
        if not source_list:
            source_list = list(src_map.keys())
        sources = []
        for idx, name in enumerate(source_list):
            obj = src_map.get(name) or {}
            ast = obj.get("AST")
            if ast is None:
                continue
            sources.append(SourceFile(name, idx, ast))
        return cls(sources)

    @property
    def contracts(self):
        out = []
        for sf in self.sources:
            for n in sf.ast.get("nodes", []):
                if node_type(n) == "ContractDefinition":
                    out.append(Contract(n, sf))
        return out
