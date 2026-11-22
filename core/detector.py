"""drain-scan core.detector - the Detector base and the Finding record.

Our replacement for Slither's AbstractDetector. A detector is a plain class with:
  - class attributes `rule_id` (e.g. "R1") and `argument` (the stable CLI/registry id), and
  - a `detect(unit) -> list[Finding]` method, where `unit` is a core.ast.Unit.

No Slither types, no SlithIR, no registration side effects. The driver and the scanner load
the Detector subclass from a module, call `detect(unit)`, and read the Findings below.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """One flagged drain surface. `line` is 1-indexed; contract/function may be None when a
    rule anchors at a coarser granularity."""
    rule_id: str
    file: str
    line: Optional[int]
    contract: Optional[str]
    function: Optional[str]
    message: str

    def location(self):
        """'file:line:Contract.function' (parts omitted when unknown) for reports."""
        where = self.file or "?"
        if self.line is not None:
            where += f":{self.line}"
        if self.contract and self.function:
            where += f":{self.contract}.{self.function}"
        elif self.function:
            where += f":{self.function}"
        elif self.contract:
            where += f":{self.contract}"
        return where


class Detector:
    """Base for every drain-scan rule. Subclasses set `rule_id` + `argument` and implement
    `detect`."""

    rule_id = None       # e.g. "R1"
    argument = None      # stable id, mirrors the Slither-era ARGUMENT / rules.tsv join key
    name = ""            # short human label
    help = ""            # one-line description

    def detect(self, unit):
        """Return a list[Finding] for `unit` (a core.ast.Unit)."""
        raise NotImplementedError
