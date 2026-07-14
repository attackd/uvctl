"""Name, suffix, and requirement-name validation.

Trust role: pure functions, no filesystem or privilege access. Every value
validated here (executable names discovered in a scratch bin dir, the user's
``--suffix`` string, ``uvctl link`` names, package specs) is
attacker-influenced and must be validated *before* any escalated or
cross-user operation consumes it. Each rule below defends against a concrete
attack; the docstrings name it.

This module deliberately avoids the third-party ``packaging`` library: per the
dependency policy uvctl splits requirement names with stdlib ``re``
only. It does not validate full specifiers; ``uv`` does that.
"""

from __future__ import annotations

import re

# Conservative charset shared by executable names, suffixes, and link names:
# ASCII letters, digits, and ``. _ + - @``. Everything else is rejected before
# it can become part of a path or a symlink name.
_NAME_CHARSET = re.compile(r"\A[A-Za-z0-9._+@-]+\Z")

# Leading PEP 508 distribution name: match only the name, then cut. Extras,
# specifiers, markers, and URLs are handled by ``uv`` downstream.
_LEADING_NAME = re.compile(r"\A\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

_SUFFIX_MAX_LEN = 32


class ValidationError(ValueError):
    """Raised when an attacker-influenced value fails a safety rule."""


def normalize_requirement_name(spec: str) -> str:
    """Extract and PEP 503-normalize the project name from a requirement spec.

    Handles specs like ``black``, ``black[d]``, ``black==24.4.2``,
    ``black[d]==24.4.2``, and leading whitespace. The normalized name is the
    directory key and ledger key, so ``install black==24.4.2 --suffix @311``
    and a later ``uninstall black --suffix @311`` resolve identically.

    Args:
        spec: A requirement string as typed by the user (name, optionally with
            extras and/or a version specifier).

    Returns:
        The PEP 503-normalized project name (lowercase, runs of ``-_.``
        collapsed to a single ``-``).

    Raises:
        ValidationError: If no leading PEP 508 name can be extracted. Callers
            passing ``--from`` URLs must extract the requested tool name before
            calling this function.
    """
    match = _LEADING_NAME.match(spec)
    if match is None:
        raise ValidationError(f"cannot extract a project name from {spec!r}")
    name = match.group(1)
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_executable_name(name: str) -> str:
    """Validate an executable/link name discovered in package metadata.

    Args:
        name: A bare command name (a basename, never a path).

    Returns:
        ``name`` unchanged, once proven safe.

    Raises:
        ValidationError: On any of the following, each mapped to its threat:
            path separators or ``.``/``..`` (directory traversal / escaping
            ``bin_dir``); a leading ``-`` (argv confusion when the name is
            later passed to a subprocess); whitespace or NUL (shell/quoting
            and truncation bugs); characters outside the conservative charset;
            or an empty string.
    """
    if not name:
        raise ValidationError("empty executable name")
    if "/" in name or "\\" in name:
        raise ValidationError(f"path separator in name: {name!r}")
    if name in (".", ".."):
        raise ValidationError(f"reserved name: {name!r}")
    if "\x00" in name:
        raise ValidationError(f"NUL byte in name: {name!r}")
    if name.startswith("-"):
        raise ValidationError(f"leading dash (argv confusion): {name!r}")
    if not _NAME_CHARSET.match(name):
        raise ValidationError(f"disallowed character in name: {name!r}")
    return name


def validate_suffix(suffix: str) -> str:
    """Validate the user's ``--suffix`` string.

    The suffix becomes part of a scratch directory name and part of the
    symlink names created in ``bin_dir``, so it carries the same charset rules
    as executable names plus a length bound and an explicit ``..`` reject.

    Args:
        suffix: The suffix as typed (uvctl passes it through verbatim; it does
            not require, strip, or add a leading ``@``).

    Returns:
        ``suffix`` unchanged, once proven safe.

    Raises:
        ValidationError: On empty input, a path separator, whitespace, a
            ``..`` substring (traversal), length over 32, or any character
            outside the conservative charset.
    """
    if not suffix:
        raise ValidationError("empty suffix")
    if len(suffix) > _SUFFIX_MAX_LEN:
        raise ValidationError(f"suffix too long (>{_SUFFIX_MAX_LEN}): {suffix!r}")
    if "/" in suffix or "\\" in suffix:
        raise ValidationError(f"path separator in suffix: {suffix!r}")
    if ".." in suffix:
        raise ValidationError(f"'..' in suffix: {suffix!r}")
    if any(ch.isspace() for ch in suffix):
        raise ValidationError(f"whitespace in suffix: {suffix!r}")
    if not _NAME_CHARSET.match(suffix):
        raise ValidationError(f"disallowed character in suffix: {suffix!r}")
    return suffix
