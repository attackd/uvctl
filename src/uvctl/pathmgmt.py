"""PATH management and shell/env emitters.

Trust role: writes ``/etc/profile.d/uvctl.sh`` (during setup, via a caller in
:mod:`uvctl.cli`); otherwise this module only *returns* text. It holds no
privilege and reads no attacker-controlled input beyond the configured paths.

This module is the single source of truth for two things every other emitter
must consume rather than reinvent:

1. The **trailing-append rule**: the shared bin dir is always appended, never
   prepended (unless the user consciously opts in), so shared tools cannot
   shadow system binaries.
2. The **canonical system PATH** used to build the deterministic ``env --cron``
   line.

Every value interpolated into shell text is emitted inside double quotes and
escaped for that context (paths can be user-influenced via ``UVCTL_*``
overrides, and unquoted ``eval`` of user-influenced text is an injection bug).
"""

from __future__ import annotations

# Fixed, deterministic system directories for the crontab PATH line. This list
# must NOT incorporate the caller's live PATH: doing so would make the output
# vary by generating shell and could smuggle per-user dirs into a system
# crontab. The shared bin dir is appended after these, in trailing position.
CANONICAL_SYSTEM_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)

_PROFILE_D_HEADER = (
    "# uvctl: shared uv tool bin dir. Appended (never prepended) so shared\n"
    "# tools cannot shadow system binaries.\n"
)


def _dq(value: str) -> str:
    r"""Escape a string for safe interpolation inside a double-quoted shell word.

    Args:
        value: The raw string (typically a filesystem path).

    Returns:
        ``value`` with ``\\``, ``"``, ``$``, and backtick backslash-escaped, so
        it can be dropped between double quotes without introducing command
        substitution, variable expansion, or quote-breakout.
    """
    out = []
    for ch in value:
        if ch in '\\"$`':
            out.append("\\")
        out.append(ch)
    return "".join(out)


def path_contains(path_value: str, bin_dir: str) -> bool:
    """Report whether ``bin_dir`` is already an exact segment of ``path_value``.

    Uses colon-delimited segment matching (``:dir:``) so ``/opt/uv/bin`` does
    not spuriously match a neighbor like ``/opt/uv/binary``.

    Args:
        path_value: A ``PATH``-style colon-separated string (may be empty).
        bin_dir: The shared bin directory to look for.

    Returns:
        True if ``bin_dir`` appears as a complete PATH segment.
    """
    return f":{bin_dir}:" in f":{path_value}:"


def env_path_line(bin_dir: str, *, prepend: bool = False) -> str:
    """Return the guarded, empty-safe shell line that adds ``bin_dir`` to PATH.

    The guard (``case ... esac``) makes a captured copy idempotent and correct
    when sourced later in a different shell. ``${PATH:+${PATH}:}`` ensures an
    empty or unset PATH yields ``bin_dir`` alone rather than a leading empty
    element (which POSIX treats as the current directory — a security
    regression).

    Args:
        bin_dir: The shared bin directory.
        prepend: If True, place ``bin_dir`` first (shared tools win over system
            binaries). Off by default and never the default anywhere; only for
            callers who consciously want it.

    Returns:
        A single line of shell, no trailing newline.
    """
    q = _dq(bin_dir)
    if prepend:
        assignment = f'export PATH="{q}${{PATH:+:${{PATH}}}}"'
    else:
        assignment = f'export PATH="${{PATH:+${{PATH}}:}}{q}"'
    return f'case ":${{PATH}}:" in *":{q}:"*) ;; *) {assignment} ;; esac'


def profile_d_snippet(bin_dir: str) -> str:
    """Return the static, guarded content for ``/etc/profile.d/uvctl.sh``.

    Always the guarded static form — never generated from live ``env`` output,
    because profile.d is the captured context by definition and live output
    would bake in the generating shell's environment.

    Args:
        bin_dir: The shared bin directory.

    Returns:
        File content ending in a newline.
    """
    return _PROFILE_D_HEADER + env_path_line(bin_dir) + "\n"


def env_output(
    bin_dir: str,
    tool_dir: str,
    current_path: str,
    *,
    prepend: bool = False,
) -> str:
    """Return the shell to emit for ``eval "$(uvctl env)"``.

    Emits the PATH line only when ``current_path`` does not already contain
    ``bin_dir`` (the command substitution runs uvctl as a child of the same
    shell, so the live check is accurate at application time). Always exports
    the ``UV_TOOL_DIR`` pair so plain ``uv``/``uvx`` become shared-aware after
    eval. Every value is quoted.

    Args:
        bin_dir: The shared bin directory.
        tool_dir: The shared tool directory (``UV_TOOL_DIR``).
        current_path: The caller's live ``PATH`` at invocation.
        prepend: Forwarded to :func:`env_path_line`.

    Returns:
        Shell text ending in a newline.
    """
    lines: list[str] = []
    if not path_contains(current_path, bin_dir):
        lines.append(env_path_line(bin_dir, prepend=prepend))
    lines.append(f'export UV_TOOL_DIR="{_dq(tool_dir)}"')
    lines.append(f'export UV_TOOL_BIN_DIR="{_dq(bin_dir)}"')
    return "\n".join(lines) + "\n"


def cron_path_line(bin_dir: str) -> str:
    """Return a complete, deterministic crontab ``PATH=`` assignment.

    Built from :data:`CANONICAL_SYSTEM_PATH` plus ``bin_dir`` in trailing
    position. Never incorporates the caller's live PATH, so the output is
    byte-identical across shells and pasting it twice is harmless.

    Args:
        bin_dir: The shared bin directory (placed last).

    Returns:
        A single ``PATH=...`` line, no trailing newline (cron variable syntax,
        not shell — no quoting).
    """
    return "PATH=" + ":".join((*CANONICAL_SYSTEM_PATH, bin_dir))


_CRON_HEADER = (
    "# Place at the top of the crontab, before any job lines.\n"
    "# Note: this PATH applies to every job in this crontab.\n"
    "# Alternative: prefix individual jobs with `uvctl run -- <tool>` instead.\n"
)


def cron_snippet(bin_dir: str) -> str:
    """Return the full commented crontab block for ``uvctl env --cron``.

    Args:
        bin_dir: The shared bin directory (placed last in the PATH line).

    Returns:
        The comment header followed by the deterministic PATH line, ending in a
        newline.
    """
    return _CRON_HEADER + cron_path_line(bin_dir) + "\n"
