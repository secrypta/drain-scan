"""drain-scan core.compile - produce an AST from a .sol via solc (subprocess only).

solc is an external compiler, invoked as a subprocess; we never link Slither/crytic. The
output is solc's `--combined-json ast`, i.e. a per-source compact AST:

    {"sourceList": [name, ...],
     "sources": {name: {"AST": <SourceUnit node>, "id": n}, ...},
     ...}

The caller feeds that dict to core.ast.Unit.from_compile().

solc version selection: the harness pins a default solc (`solc-select use`, as all.sh does),
but some vendored fixtures pin an exact older pragma (e.g. Uniswap Permit2 is `pragma solidity
0.8.17;`) that the pinned compiler refuses. So compile_source reads the file's pragma and, when
a solc-select-installed version satisfies it better, invokes that version's binary directly
(highest installed version satisfying the pragma). Files whose pragma the default solc already
satisfies (the common `^0.8.x`) keep using the default - behaviour is unchanged for them.
"""
import json
import os
import re
import shutil
import signal
import subprocess


class CompileError(Exception):
    """solc failed to compile, or its AST could not be parsed."""


# ------------------------------- subprocess (leak-safe) -------------------------------
#
# solc is run in its own session (start_new_session=True), i.e. its own process group. The
# invoked binary is the REAL solc (see _default_solc_bin / _installed_solc), not the solc-select
# PATH wrapper - the wrapper is a short-lived Python process that execs/forks the real compiler
# as a grandchild, so on a timeout subprocess would reap only the wrapper and orphan the real
# solc, which then hangs forever. Even calling the real binary directly, a timeout (or any
# interruption) must tear down the WHOLE group so no child/grandchild leaks: killpg + wait,
# wrapped in try/finally. These orphans accumulating (1800+) is what exhausted VM memory.

def _kill_group(proc):
    """SIGKILL the subprocess's entire process group, then fall back to killing the direct
    child. Best-effort: swallow races where the group/child is already gone."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _assert_native_binary(binp):
    """Refuse to execute anything that is not a native ELF binary.

    A corrupt solc install can leave an artifact that is really a `#!...python` solc-select
    wrapper (or a symlink to one) instead of the compiler. Executing it re-execs solc-select,
    which resolves the active version and re-runs the SAME artifact, forking without bound
    until the machine's PIDs/memory are exhausted (observed: a 200+ process chain that froze
    the VM). Reading the magic bytes of the resolved target and requiring ELF makes that
    impossible: a wrapper (starts with b'#!') or any non-ELF file raises here instead of being
    spawned. Raises OSError, which callers already map to CompileError / 'version unavailable'."""
    real = os.path.realpath(binp)
    try:
        with open(real, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise OSError(f"solc binary not readable: {binp} -> {real}: {exc}")
    if magic != b"\x7fELF":
        raise OSError(
            f"refusing to execute non-ELF solc binary (corrupt install / solc-select wrapper "
            f"-> recursive fork-bomb risk): {binp} -> {real} (magic {magic!r})"
        )


def _run_solc(cmd, timeout):
    """Run a solc command in its own process group and return (returncode, stdout, stderr).

    On timeout the whole group is SIGKILLed and reaped before re-raising TimeoutExpired, so no
    orphaned solc survives. A try/finally guarantees the same teardown on any other interruption
    (e.g. KeyboardInterrupt), so processes never leak out of this function. Raises OSError if the
    binary could not be spawned."""
    _assert_native_binary(cmd[0])
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait()
            raise
        return proc.returncode, stdout, stderr
    finally:
        # Any non-timeout interruption (the return path and the TimeoutExpired path already
        # settled the process): if it is somehow still alive, do not let it leak.
        if proc.poll() is None:
            _kill_group(proc)
            proc.wait()


# ------------------------- pragma -> solc version selection -------------------------

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_CLAUSE_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)")


def _vtuple(ver):
    return tuple(int(x) for x in ver.split("."))


def _solc_select_artifacts_dir():
    """Where solc-select keeps installed compilers, honoring its env + venv layout."""
    env = os.environ.get("SOLC_SELECT_INSTALL_DIR")
    if env:
        return os.path.join(env, "artifacts")
    venv = os.environ.get("VIRTUAL_ENV")
    candidates = []
    if venv:
        candidates.append(os.path.join(venv, ".solc-select", "artifacts"))
    candidates.append(os.path.expanduser("~/.solc-select/artifacts"))
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None


def _installed_solc():
    """{version_str: binary_path} for every solc-select-installed compiler."""
    base = _solc_select_artifacts_dir()
    out = {}
    if not base:
        return out
    for name in os.listdir(base):
        if not name.startswith("solc-"):
            continue
        ver = name[len("solc-"):]
        binp = os.path.join(base, name, f"solc-{ver}")
        if os.path.isfile(binp) and os.access(binp, os.X_OK):
            out[ver] = binp
    return out


def _active_solc_version():
    """The version solc-select currently has active, read from its `global-version` file (next
    to the artifacts dir). None if it cannot be determined."""
    base = _solc_select_artifacts_dir()
    if not base:
        return None
    gv = os.path.join(os.path.dirname(base), "global-version")
    try:
        with open(gv) as fh:
            ver = fh.read().strip()
    except OSError:
        return None
    return ver or None


def _default_solc_bin():
    """The real solc binary to use for the common case (pragma the active compiler satisfies).

    Resolve the active solc-select version to its REAL binary under artifacts, bypassing the
    `solc` PATH shim (a Python solc-select wrapper that forks the real compiler as a grandchild
    - on a timeout that grandchild orphans and hangs). Fall back to `shutil.which('solc')` only
    when the active version's artifact cannot be located."""
    active = _active_solc_version()
    if active:
        installed = _installed_solc()
        if active in installed:
            return installed[active]
    return shutil.which("solc")


def _parse_pragma(text):
    m = _PRAGMA_RE.search(text)
    return m.group(1).strip() if m else None


def _satisfies(ver, constraint):
    """Does version `ver` (e.g. '0.8.17') satisfy a solidity pragma `constraint`? Handles the
    operators that appear in the corpus: exact / = , ^ , ~ , >= , <= , > , < , space-ANDed."""
    v = _vtuple(ver)
    clauses = _CLAUSE_RE.findall(constraint)
    if not clauses:
        return False
    for op, a, b, c in clauses:
        want = (int(a), int(b), int(c))
        if op in ("", "="):
            if v != want:
                return False
        elif op == ">=":
            if not v >= want:
                return False
        elif op == "<=":
            if not v <= want:
                return False
        elif op == ">":
            if not v > want:
                return False
        elif op == "<":
            if not v < want:
                return False
        elif op == "^":
            # npm caret: >= want, < next (left-most non-zero) bump
            upper = (want[0] + 1, 0, 0) if want[0] > 0 else (0, want[1] + 1, 0)
            if not (v >= want and v < upper):
                return False
        elif op == "~":
            upper = (want[0], want[1] + 1, 0)
            if not (v >= want and v < upper):
                return False
    return True


def _solc_for_pragma(text, default_bin):
    """Pick a solc binary for the file. Prefer the default (PATH/active) when it satisfies the
    pragma; otherwise the highest installed version that does. Returns a binary path."""
    constraint = _parse_pragma(text)
    if not constraint:
        return default_bin
    installed = _installed_solc()
    satisfying = [ver for ver in installed if _satisfies(ver, constraint)]
    if not satisfying:
        return default_bin
    # If the default already satisfies, keep it (stable behaviour for the common ^0.8.x case).
    default_ver = _solc_version(default_bin) if default_bin else None
    if default_ver and _satisfies(default_ver, constraint):
        return default_bin
    best = max(satisfying, key=_vtuple)
    return installed[best]


_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _solc_version(binp):
    try:
        _rc, stdout, _stderr = _run_solc([binp, "--version"], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _VERSION_RE.search(stdout or "")
    return m.group(1) if m else None


# ------------------------------- compile -------------------------------

def compile_source(sol_path, allow_paths=None, solc=None, timeout=180):
    """Compile one .sol file with solc and return the combined-json dict (with the AST).

    allow_paths: passed to solc --allow-paths so the file's relative imports (vendored OZ,
    Permit2, etc.) resolve. solc: an explicit binary (bypasses pragma selection); otherwise the
    binary is chosen from the file's pragma (see module docstring), defaulting to the first
    `solc` on PATH. Raises CompileError on any failure (never returns a partial AST silently).
    """
    sol_path = os.path.abspath(sol_path)
    if not os.path.isfile(sol_path):
        raise CompileError(f"source not found: {sol_path}")

    if solc:
        solc_bin = solc
    else:
        default_bin = _default_solc_bin()
        if not default_bin:
            raise CompileError("solc not found on PATH (run: solc-select use <version>)")
        try:
            with open(sol_path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            raise CompileError(f"could not read source: {exc}")
        solc_bin = _solc_for_pragma(text, default_bin)

    cmd = [solc_bin, "--combined-json", "ast"]
    if allow_paths:
        cmd += ["--allow-paths", allow_paths]
    cmd.append(sol_path)
    try:
        returncode, stdout, stderr = _run_solc(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CompileError(f"solc timeout after {timeout}s on {sol_path}")
    except OSError as exc:
        raise CompileError(f"solc could not be executed: {exc}")

    if returncode != 0:
        err = (stderr or stdout or "").strip()
        raise CompileError(f"solc rc={returncode}: {err[:600]}")
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        raise CompileError(f"could not parse solc AST JSON: {exc}")
    if not data.get("sources"):
        raise CompileError(f"solc produced no AST for {sol_path}")
    _assert_compact_ast(data["sources"], sol_path)
    return data


def _assert_compact_ast(sources, sol_path):
    """Refuse a legacy (pre-0.8) AST instead of silently analyzing nothing.

    solc <0.8 emits a LEGACY AST under `--combined-json ast`: the SourceUnit is keyed by `name`
    / `children` with no `nodeType`, which the compact-AST core (core.ast, keyed on `nodeType` /
    `nodes`) reads as zero contracts. That produces an EMPTY unit and therefore a SILENT clean
    verdict - a false "safe" on a pre-0.8 wallet, strictly worse than a visible miss. drain-scan
    supports Solidity >=0.8 (the compact AST); a pre-0.8 source is out of scope and must fail
    loudly here (callers map CompileError to a reported error, never to a clean pass)."""
    for obj in sources.values():
        ast = (obj or {}).get("AST")
        if isinstance(ast, dict) and "nodeType" not in ast and ("children" in ast or "name" in ast):
            raise CompileError(
                f"legacy (pre-0.8) AST from solc for {sol_path}: drain-scan analyzes Solidity "
                f">=0.8 (compact AST). A pre-0.8 source cannot be analyzed and must not be reported "
                f"as clean - pin a >=0.8 compiler/pragma or exclude the file."
            )
