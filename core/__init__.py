"""drain-scan analysis core.

A small, self-contained static-analysis layer over the solidity compiler's own AST. It
replaces the previous dependence on Slither / SlithIR: importing the slither package is
forbidden here (and in the detectors, the driver and the scanner). solc is used only as an external
compiler (invoked as a subprocess) to produce the AST; everything above that - node
navigation, light dataflow, the detector interface - is ours (MIT).

Layers:
  compile  - run solc and return its combined-json AST
  ast      - navigate the AST (sources / contracts / functions / expression nodes)
  dataflow - light, name-level taint / reachability helpers (grows with the rule clusters)
  detector - the Detector base and the Finding record every rule emits
"""
