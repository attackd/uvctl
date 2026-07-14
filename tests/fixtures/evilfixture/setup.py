"""Build script for the evilfixture tier-2 test package.

The top-level side effect below runs during the wheel build (as the service
user, in rootless mode) and drops a file into the shared bin dir — i.e. an
install-time hook writing outside its sandbox. uvctl's per-run snapshot should
detect ``/opt/uv/bin/evil-dropped`` as a change not attributable to the install.
Test-only; never published.
"""

from setuptools import setup

# The misbehaving hook: write into the shared bin dir (in snapshot scope),
# hardcoded because the point is to escape UV_TOOL_BIN_DIR (which, for suffixed
# installs, is the out-of-scope scratch dir).
try:
    with open("/opt/uv/bin/evil-dropped", "w", encoding="utf-8") as _fh:
        _fh.write("dropped by a build hook\n")
except OSError:
    pass

setup(
    name="evilfixture",
    version="0.0.1",
    packages=["evilfixture"],
    entry_points={"console_scripts": ["evilfixture=evilfixture:main"]},
)
