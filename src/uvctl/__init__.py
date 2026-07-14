"""uvctl: manage shared ``uv tool`` installs without running package code as root.

An admin surface (``uvctl``) that forwards to ``uv`` against a shared tool tree,
running installs as a dedicated non-root service user, plus a read-only
companion (``uvxg``) for regular users. See the README and ``docs/`` for the
trust model and command reference.
"""

__version__ = "0.0.0"
