"""Enforce the stdlib-only runtime dependency policy (tier 1, an AC item).

Two checks: the runtime distribution declares nothing beyond the conditional
`tomli` backport, and no runtime module imports a third-party package
(including `packaging`). See docs/security.rst item 16 (dependency policy).
"""

import ast
import pathlib
from importlib.metadata import requires

# Everything uvctl's runtime is permitted to import: the standard library
# surface it actually uses, the `tomllib`/`tomli` config reader, and itself.
_ALLOWED_TOPLEVEL = {
    "__future__",
    "argparse",
    "ast",
    "collections",
    "ctypes",
    "dataclasses",
    "grp",
    "hashlib",
    "json",
    "os",
    "pathlib",
    "pwd",
    "re",
    "shutil",
    "stat",
    "subprocess",
    "sys",
    "syslog",
    "tempfile",
    "time",
    "types",
    "typing",
    "tomllib",
    "tomli",
    "uvctl",
}

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "uvctl"


def _toplevel_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # level > 0 means an intra-package relative import (e.g. `from .`)
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def test_no_thirdparty_runtime_imports():
    seen: set[str] = set()
    for py in sorted(_SRC.glob("*.py")):
        seen |= _toplevel_imports(py)
    unexpected = seen - _ALLOWED_TOPLEVEL
    assert not unexpected, f"disallowed runtime imports: {sorted(unexpected)}"
    assert "packaging" not in seen


def test_declared_runtime_deps_are_only_tomli():
    reqs = requires("uvctl") or []
    for req in reqs:
        if "extra ==" in req:
            continue  # optional extras (e.g. [docs]) are allowed
        name = req.split(";")[0].strip()
        for sep in ("[", " ", "=", "<", ">", "~", "!"):
            name = name.split(sep)[0]
        assert name == "tomli", f"disallowed runtime dependency declared: {req!r}"
