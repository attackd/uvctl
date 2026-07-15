"""Console entry points for ``uvctl`` and ``uvxg``.

Trust role: argument dispatch. ``main`` routes uvctl-native subcommands
(``setup``, ``link``, ``config``, ``env``, ``run``, ``verify``) and otherwise
forwards to ``uv`` via :mod:`uvctl.escalate` (the only path that escalates).
The non-escalating subcommands (``config``, ``env``, ``run``, ``verify``) and
``main_uvxg`` never call into :mod:`uvctl.escalate`.

Most decision logic is factored into small pure functions (``split_suffix``,
``resolve_run_target``, ``verify_ledger``, ``format_config``, ``plan_link``,
``build_uvxg_argv`` / ``build_uvxg_env``) so it is unit-testable without running
subprocesses or mutating the system.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

from . import config as config_mod
from . import escalate, ledger, pathmgmt, snapshot, suffix, validate

#: uvctl-native subcommands; anything else is forwarded to ``uv``.
NATIVE_SUBCOMMANDS = frozenset({"setup", "link", "config", "env", "run", "verify"})

#: Exit code for an integrity finding (distinct from uv's own codes).
_EXIT_INTEGRITY = 3


class CliError(Exception):
    """A user-facing error; ``main`` prints it and exits non-zero."""


# --- pure helpers ------------------------------------------------------------


def split_suffix(args: list[str]) -> tuple[str | None, list[str]]:
    """Extract and strip ``--suffix`` (both forms) from a forwarded arg list.

    Args:
        args: The arguments intended for ``uv`` (after ``uvctl``).

    Returns:
        A ``(suffix, remaining)`` pair; ``suffix`` is None when absent.

    Raises:
        CliError: If ``--suffix`` is given without a value.
    """
    suffix: str | None = None
    rest: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--suffix":
            if i + 1 >= len(args):
                raise CliError("--suffix requires a value")
            suffix = args[i + 1]
            i += 2
            continue
        if arg.startswith("--suffix="):
            suffix = arg.split("=", 1)[1]
            i += 1
            continue
        rest.append(arg)
        i += 1
    return suffix, rest


def is_tool_install_or_uninstall(args: list[str]) -> bool:
    """Whether ``args`` begins with ``tool install`` or ``tool uninstall``."""
    return args[:2] in (["tool", "install"], ["tool", "uninstall"])


def resolve_run_target(bin_dir: str, args: list[str]) -> tuple[str, list[str]]:
    """Resolve ``uvctl run`` arguments to a strict ``bin_dir`` target.

    Strips a leading ``--`` separator, validates the tool name (a bare
    basename), and requires the executable to exist in ``bin_dir``. No PATH
    search and no ephemeral fallback: automation wants the pinned tool or a
    loud failure.

    Args:
        bin_dir: The shared bin directory.
        args: Everything after ``run`` (optionally led by ``--``).

    Returns:
        A ``(target_path, argv)`` pair where ``argv[0]`` is the tool name.

    Raises:
        CliError: If no tool is given or it is not installed in ``bin_dir``.
        ValidationError: If the tool name fails basename validation.
    """
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise CliError("usage: uvctl run -- <tool> [args...]")
    tool = validate.validate_executable_name(args[0])
    target = os.path.join(bin_dir, tool)
    if not (os.path.isfile(target) and os.access(target, os.X_OK)):
        raise CliError(
            f"{tool!r} is not installed in {bin_dir} "
            "(uvctl run does not fall back to an ephemeral download)"
        )
    return target, [tool, *args[1:]]


def verify_ledger(ledger_path: str = ledger.LEDGER_PATH) -> list[str]:
    """Check every ledger-recorded link against current reality.

    For each active install's executables: the link must still exist, still be
    a symlink, and still resolve to the recorded target. Neighbors uvctl never
    touched are out of scope by construction (only ledger claims are checked).

    Args:
        ledger_path: Path to the install ledger.

    Returns:
        A list of human-readable discrepancy strings (empty when healthy).
    """
    data = ledger.load_ledger(ledger_path)
    problems: list[str] = []
    for record in data["installs"]:  # type: ignore[union-attr]
        if record.get("removed"):
            continue
        for exe in record.get("executables", []):
            link = exe.get("link")
            target = exe.get("target")
            if not os.path.lexists(link):
                problems.append(f"missing: {link} (recorded for {record['package']})")
            elif not os.path.islink(link):
                problems.append(f"not a symlink: {link}")
            elif os.path.realpath(link) != os.path.realpath(target):
                problems.append(
                    f"retargeted: {link} -> {os.path.realpath(link)} "
                    f"(expected {target})"
                )
    return problems


def format_config(
    cfg: config_mod.Config,
    *,
    current_path: str,
    mode: str | None,
    mode_reason: str | None,
) -> list[str]:
    """Render ``uvctl config`` output lines.

    Args:
        cfg: The resolved configuration.
        current_path: The caller's ``PATH`` (for the shared-dir diagnostic).
        mode: Detected operating mode, or None if undetermined.
        mode_reason: Explanation of the mode (or why it is undetermined).

    Returns:
        Output lines.
    """
    lines = ["uvctl configuration:"]
    for name in (
        "tool_dir",
        "bin_dir",
        "service_user",
        "uv_path",
        "python_install_dir",
        "cache_dir",
    ):
        setting = getattr(cfg, name)
        value = setting.value if setting.value is not None else "(unset)"
        lines.append(f"  {name} = {value}  [{setting.source}]")
    lines.append(f"  mode = {mode or 'undetermined'}  ({mode_reason})")
    on_path = pathmgmt.path_contains(current_path, cfg.bin_dir.value or "")
    lines.append(f"  shared bin dir on current PATH: {'yes' if on_path else 'no'}")
    overrides = cfg.active_env_overrides()
    if overrides:
        lines.append("  active environment overrides:")
        for key, setting in overrides:
            lines.append(f"    {key} <- {setting.source} = {setting.value}")
    return lines


def plan_link(
    cfg: config_mod.Config, name: str, bin_dir: str | None
) -> tuple[str, str]:
    """Validate a ``link`` name and compute the (link_path, target) pair.

    Args:
        cfg: The resolved configuration.
        name: The requested additional admin command name.
        bin_dir: Override bin dir, or None to use the configured one.

    Returns:
        A ``(link_path, uvctl_target)`` pair.

    Raises:
        ValidationError: If ``name`` fails executable-name validation.
        CliError: If the running ``uvctl`` executable cannot be located.
    """
    validate.validate_executable_name(name)
    effective_bin = bin_dir or cfg.bin_dir.value
    target = shutil.which("uvctl") or sys.argv[0]
    if not target or not os.path.exists(target):
        raise CliError("cannot locate the uvctl executable to link to")
    return os.path.join(effective_bin, name), os.path.realpath(target)


def build_uvxg_argv(uv_path: str, args: list[str]) -> list[str]:
    """Build the ``uv tool run <args>`` vector for ``uvxg``."""
    return [uv_path, "tool", "run", *args]


def build_uvxg_env(base_env: dict[str, str], cfg: config_mod.Config) -> dict[str, str]:
    """Return ``base_env`` with the shared ``UV_TOOL_DIR`` pair set for ``uvxg``.

    ``uvxg`` never escalates, so it inherits the caller's own environment and
    only overlays the shared-location pointers.

    Args:
        base_env: The caller's environment.
        cfg: The resolved configuration.

    Returns:
        A new environment mapping.
    """
    env = dict(base_env)
    env["UV_TOOL_DIR"] = cfg.tool_dir.value  # type: ignore[assignment]
    env["UV_TOOL_BIN_DIR"] = cfg.bin_dir.value  # type: ignore[assignment]
    return env


# --- subcommands -------------------------------------------------------------


def _detect_mode(cfg: config_mod.Config) -> tuple[str | None, str]:
    """Detect the operating mode, tolerating an un-set-up system."""
    bin_dir = cfg.bin_dir.value
    user = cfg.service_user.value
    if not user:
        return None, "no service user configured (plain mode)"
    try:
        writable = config_mod.path_writable_by_user(bin_dir, user)
    except (OSError, KeyError) as exc:
        return None, f"cannot determine ({exc}); has `uvctl setup` run?"
    mode = config_mod.detect_mode(writable)
    why = (
        f"{bin_dir} is writable by {user}"
        if writable
        else f"{bin_dir} is not writable by {user}"
    )
    return mode, why


def _print_overrides(cfg: config_mod.Config) -> None:
    """Print any active env overrides to stderr (required on every install)."""
    for key, setting in cfg.active_env_overrides():
        print(
            f"uvctl: note: {key} overridden by {setting.source} = {setting.value}",
            file=sys.stderr,
        )


def cmd_config(rest: list[str], cfg: config_mod.Config | None = None) -> int:
    """Run ``uvctl config``."""
    cfg = cfg or config_mod.resolve()
    mode, reason = _detect_mode(cfg)
    lines = format_config(
        cfg,
        current_path=os.environ.get("PATH", ""),
        mode=mode,
        mode_reason=reason,
    )
    print("\n".join(lines))
    return 0


def cmd_env(rest: list[str], cfg: config_mod.Config | None = None) -> int:
    """Run ``uvctl env`` / ``uvctl env --cron``."""
    parser = argparse.ArgumentParser(prog="uvctl env")
    parser.add_argument(
        "--cron", action="store_true", help="emit a full crontab PATH line"
    )
    parser.add_argument(
        "--prepend",
        action="store_true",
        help="prepend the shared bin dir so shared tools win over system "
        "binaries (NOT the default; use consciously)",
    )
    ns = parser.parse_args(rest)
    cfg = cfg or config_mod.resolve()
    if ns.cron:
        sys.stdout.write(pathmgmt.cron_snippet(cfg.bin_dir.value))
    else:
        sys.stdout.write(
            pathmgmt.env_output(
                cfg.bin_dir.value,
                cfg.tool_dir.value,
                os.environ.get("PATH", ""),
                prepend=ns.prepend,
            )
        )
    return 0


def cmd_run(rest: list[str], cfg: config_mod.Config | None = None) -> int:
    """Run ``uvctl run -- <tool> [args...]`` by ``execv`` (never returns on success)."""
    cfg = cfg or config_mod.resolve()
    target, argv = resolve_run_target(cfg.bin_dir.value, rest)
    os.execv(target, argv)


def cmd_verify(
    rest: list[str],
    cfg: config_mod.Config | None = None,
    ledger_path: str = ledger.LEDGER_PATH,
) -> int:
    """Run ``uvctl verify``; exit non-zero on any discrepancy."""
    problems = verify_ledger(ledger_path)
    for problem in problems:
        print(f"uvctl verify: {problem}", file=sys.stderr)
    if problems:
        print(f"uvctl verify: {len(problems)} discrepancy(ies) found", file=sys.stderr)
        return 1
    print("uvctl verify: all ledger-recorded links are intact")
    return 0


def cmd_link(rest: list[str], cfg: config_mod.Config | None = None) -> int:
    """Run ``uvctl link <name> [--bin-dir DIR]``."""
    parser = argparse.ArgumentParser(prog="uvctl link")
    parser.add_argument("name")
    parser.add_argument("--bin-dir", default=None)
    ns = parser.parse_args(rest)
    cfg = cfg or config_mod.resolve()
    link_path, target = plan_link(cfg, ns.name, ns.bin_dir)
    escalate.run_as_service_user(
        ["ln", "-s", target, link_path],
        service_user=cfg.service_user.value,
    )
    print(f"uvctl: linked {link_path} -> {target}")
    return 0


def should_drop_privileges(
    *,
    euid: int,
    is_setup: bool,
    as_root: bool,
    service_user: str | None,
    mode: str | None,
) -> bool:
    """Decide whether to irrevocably drop to the service user at startup.

    True only in the rootless invariant case: running as root, a service user is
    configured, the command is not ``setup`` (which legitimately needs root),
    and ``--as-root`` was not requested. System-bin mode keeps root because its
    narrow symlink/ledger steps need it.

    Args:
        euid: The current effective uid.
        is_setup: Whether the command is ``setup``.
        as_root: Whether a true root install was explicitly requested.
        service_user: The configured service user (falsy → no drop).
        mode: The detected operating mode.

    Returns:
        True if the process should drop permanently to the service user.
    """
    if euid != 0:
        return False
    if is_setup or as_root:
        return False
    if not service_user:
        return False
    return mode == config_mod.ROOTLESS


#: Never-escalating subcommands: they need no root and (``run``) exec in-process
#: with no child to drop, so they drop unconditionally when invoked as root —
#: independent of mode. This also closes the vector where an attacker who can
#: influence the environment forces system-bin detection to suppress the drop.
_NEVER_ESCALATE = frozenset({"config", "env", "run", "verify"})


def _should_drop_for_command(
    cmd: str, *, euid: int, service_user: str | None, mode: str | None, as_root: bool
) -> bool:
    """Whether to drop to the service user at startup, given the subcommand.

    Read-only, never-escalating commands drop whenever running as root; install/
    uninstall/forward paths keep root in system-bin (their narrow steps need it)
    and drop only in rootless. ``setup`` never drops.
    """
    if euid != 0 or not service_user or cmd == "setup":
        return False
    if cmd in _NEVER_ESCALATE:
        return True
    return should_drop_privileges(
        euid=euid,
        is_setup=False,
        as_root=as_root,
        service_user=service_user,
        mode=mode,
    )


def _maybe_drop_privileges(argv: list[str]) -> None:
    """Perform the one-time startup privilege drop, if applicable.

    Reads the root-owned config (a trusted read, the one thing legitimately done
    at uid 0), detects the mode, and irrevocably drops the whole process to the
    service user before any other logic runs. ``SUDO_USER`` remains in the
    environment for ledger attribution.
    """
    if os.geteuid() != 0:
        return
    cmd = argv[0] if argv else ""
    as_root = wants_root(argv, dict(os.environ))
    cfg = config_mod.resolve()
    mode, _ = _detect_mode(cfg)
    if _should_drop_for_command(
        cmd,
        euid=os.geteuid(),
        service_user=cfg.service_user.value,
        mode=mode,
        as_root=as_root,
    ):
        escalate.drop_privileges_permanently(cfg.service_user.value)


def wants_root(argv: list[str], environ: dict[str, str]) -> bool:
    """Whether a true root-owned install was explicitly requested.

    Args:
        argv: The forwarded arguments (checked for ``--as-root``).
        environ: The environment (checked for ``UVCTL_ALLOW_ROOT=1``).

    Returns:
        True if ``--as-root`` is present or ``UVCTL_ALLOW_ROOT`` is ``1``.
    """
    return "--as-root" in argv or environ.get("UVCTL_ALLOW_ROOT") == "1"


def _effective_service_user(cfg: config_mod.Config, as_root: bool) -> str | None:
    """Resolve the service user, honoring an explicit ``--as-root`` override.

    A habitual ``sudo uvctl`` (root, no ``--as-root``) silently drops to the
    service user via :func:`escalate.plan_privilege`. ``--as-root`` opts out of
    that drop and runs package code as uid 0, with a prominent warning.
    """
    if as_root and os.geteuid() == 0:
        print(
            "uvctl: WARNING: --as-root: package code will execute as uid 0; "
            "integrity checking is best-effort only in this mode",
            file=sys.stderr,
        )
        mode, _ = _detect_mode(cfg)
        ledger.emit_audit(
            "as_root",
            timestamp=ledger.now(),
            user=ledger.invoking_user(),
            mode=mode or "unknown",
        )
        return None
    return cfg.service_user.value


def _enforce_system_bin_gate(mode: str | None, cfg: config_mod.Config) -> None:
    """Refuse an install op at the front door when system-bin lacks root.

    In system-bin mode uvctl cannot obtain root on its own (the ``(uvctl)``
    sudoers grant only reaches the service user), so a non-root invocation can
    never do the right thing — refuse before any snapshot or install work
    rather than fail mid-operation. Records an audit event.
    """
    if mode == config_mod.SYSTEM_BIN and os.geteuid() != 0:
        ledger.emit_audit(
            "refused",
            timestamp=ledger.now(),
            user=ledger.invoking_user(),
            mode=mode,
            reason="system-bin-requires-root",
        )
        raise CliError(
            "system-bin mode requires root; the (uvctl) sudoers grant is "
            "sufficient only for rootless operation"
        )


def cmd_forward(argv: list[str], cfg: config_mod.Config | None = None) -> int:
    """Forward to ``uv`` (or route ``--suffix`` installs to :mod:`uvctl.suffix`)."""
    cfg = cfg or config_mod.resolve()
    as_root = wants_root(argv, dict(os.environ))
    no_verify = "--no-verify" in argv
    argv = [a for a in argv if a not in ("--as-root", "--no-verify")]
    sfx, rest = split_suffix(argv)
    is_install_op = sfx is not None or is_tool_install_or_uninstall(rest)

    if is_install_op:
        mode, _ = _detect_mode(cfg)
        _enforce_system_bin_gate(mode, cfg)
        if no_verify and mode == config_mod.SYSTEM_BIN:
            raise CliError(
                "--no-verify is not available in system-bin mode; "
                "integrity checking is mandatory"
            )

    if sfx is not None:
        if not is_tool_install_or_uninstall(rest):
            raise CliError("--suffix is only supported on tool install/uninstall")
        _print_overrides(cfg)
        if rest[1] == "install":
            return suffix.install(cfg, rest[2:], sfx, no_verify=no_verify)
        return suffix.uninstall(cfg, rest[2:], sfx)
    if is_tool_install_or_uninstall(rest):
        _print_overrides(cfg)
        svc = _effective_service_user(cfg, as_root)
        if rest[1] == "install":
            return _forward_install(
                cfg, rest[2:], service_user=svc, no_verify=no_verify
            )
        return _forward_uninstall(cfg, rest[2:], service_user=svc, no_verify=no_verify)
    # Other forwards (list, upgrade, ...): no integrity monitoring.
    result = escalate.run_uv(
        rest,
        uv_path=cfg.uv_path.value,
        tool_dir=cfg.tool_dir.value,
        bin_dir=cfg.bin_dir.value,
        python_install_dir=cfg.python_install_dir.value,
        cache_dir=cfg.cache_dir.value,
        service_user=_effective_service_user(cfg, as_root),
    )
    return result.returncode


def _plain_name(args: list[str]) -> str | None:
    """Best-effort normalized package name for the attribution anchor.

    Returns None when the name cannot be unambiguously determined (matching the
    plain-forward "verbatim" contract), in which case integrity monitoring is
    skipped rather than risking a misattributed — and destructive — rollback.
    """
    try:
        return validate.normalize_requirement_name(suffix.extract_package_spec(args))
    except (suffix.SuffixError, validate.ValidationError):
        return None


def _run_forward_uv(
    cfg: config_mod.Config, verb: str, args: list[str], service_user: str | None
):
    """Run a forwarded ``uv tool <verb> <args>`` with the shared dirs."""
    return escalate.run_uv(
        ["tool", verb, *args],
        uv_path=cfg.uv_path.value,
        tool_dir=cfg.tool_dir.value,
        bin_dir=cfg.bin_dir.value,
        python_install_dir=cfg.python_install_dir.value,
        cache_dir=cfg.cache_dir.value,
        service_user=service_user,
    )


def _rollback_plain(cfg: config_mod.Config, name: str, service_user: str | None) -> str:
    """Best-effort rollback of a plain install (``uv tool uninstall <name>``)."""
    try:
        result = _run_forward_uv(cfg, "uninstall", [name], service_user)
        return "ok" if result.returncode == 0 else "failed"
    except (escalate.EscalationError, OSError):
        return "failed"


def _forward_install(
    cfg: config_mod.Config,
    args: list[str],
    *,
    service_user: str | None,
    no_verify: bool,
) -> int:
    """Plain ``tool install`` with two-point, target-based integrity monitoring.

    uv has already linked by the time we can inspect, so the fail-closed analog
    of abort-before-linking is: report findings, best-effort rollback
    (``uv tool uninstall``), non-zero exit. Unattributed files are never
    auto-deleted (never-delete boundary).
    """
    mode, _ = _detect_mode(cfg)
    name = _plain_name(args)
    monitor = name is not None and not (no_verify and mode == config_mod.ROOTLESS)
    if name is not None and no_verify and mode == config_mod.ROOTLESS:
        ledger.emit_audit(
            "verify_skipped",
            timestamp=ledger.now(),
            user=ledger.invoking_user(),
            mode=mode or "unknown",
            pkg=name,
            path="plain",
        )

    scope = snapshot.scope_for(cfg.bin_dir.value)
    pre = pre_fp = None
    if monitor:
        pre = snapshot.Snapshot.capture(scope)
        pre_fp = snapshot.fingerprint(pre)

    result = _run_forward_uv(cfg, "install", args, service_user)
    if result.returncode != 0:
        return result.returncode

    if monitor:
        snapshot.verify_fingerprint(pre, pre_fp)
        post = snapshot.Snapshot.capture(scope)
        env_dir = suffix.plain_tool_env_dir(cfg.tool_dir.value, name)
        findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
        if findings:
            print(snapshot.format_report(findings), file=sys.stderr)
            rollback = _rollback_plain(cfg, name, service_user)
            print(
                f"uvctl: integrity findings on plain install of {name!r}; "
                f"rolled back ({rollback}); unattributed files left in place for "
                "admin review (never auto-deleted)",
                file=sys.stderr,
            )
            ledger.emit_audit(
                "integrity_finding",
                timestamp=ledger.now(),
                user=ledger.invoking_user(),
                mode=mode or "unknown",
                pkg=name,
                path="plain",
                rollback=rollback,
            )
            return _EXIT_INTEGRITY
    return 0


def _forward_uninstall(
    cfg: config_mod.Config,
    args: list[str],
    *,
    service_user: str | None,
    no_verify: bool,
) -> int:
    """Plain ``tool uninstall`` with two-point, target-based integrity monitoring.

    EXPECTED changes are deletions of this tool's entrypoints; anything else is a
    finding. There is nothing to roll back on an uninstall — report and exit
    non-zero.
    """
    mode, _ = _detect_mode(cfg)
    name = _plain_name(args)
    monitor = name is not None and not (no_verify and mode == config_mod.ROOTLESS)
    if name is not None and no_verify and mode == config_mod.ROOTLESS:
        ledger.emit_audit(
            "verify_skipped",
            timestamp=ledger.now(),
            user=ledger.invoking_user(),
            mode=mode or "unknown",
            pkg=name,
            path="plain_uninstall",
        )

    scope = snapshot.scope_for(cfg.bin_dir.value)
    pre = pre_fp = None
    if monitor:
        pre = snapshot.Snapshot.capture(scope)
        pre_fp = snapshot.fingerprint(pre)

    result = _run_forward_uv(cfg, "uninstall", args, service_user)

    if monitor:
        snapshot.verify_fingerprint(pre, pre_fp)
        post = snapshot.Snapshot.capture(scope)
        env_dir = suffix.plain_tool_env_dir(cfg.tool_dir.value, name)
        findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
        if findings:
            print(snapshot.format_report(findings), file=sys.stderr)
            ledger.emit_audit(
                "integrity_finding",
                timestamp=ledger.now(),
                user=ledger.invoking_user(),
                mode=mode or "unknown",
                pkg=name,
                path="plain_uninstall",
            )
            return _EXIT_INTEGRITY
    return result.returncode


def cmd_setup(rest: list[str]) -> int:
    """Run ``uvctl setup`` (implemented in Phase 5)."""
    from . import setup

    return setup.main(rest)


# --- entry points ------------------------------------------------------------


def _dispatch(argv: list[str]) -> int:
    """Route ``argv`` to a native subcommand or forward it to ``uv``."""
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: uvctl <setup|config|env|run|verify|link|tool ...> [args]\n"
            "       uvctl tool install <pkg> [--suffix SFX]\n"
            "See `uvctl config` for the effective settings and detected mode."
        )
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "setup":
        return cmd_setup(rest)
    if cmd == "config":
        return cmd_config(rest)
    if cmd == "env":
        return cmd_env(rest)
    if cmd == "run":
        return cmd_run(rest)
    if cmd == "verify":
        return cmd_verify(rest)
    if cmd == "link":
        return cmd_link(rest)
    return cmd_forward(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``uvctl`` admin command.

    Args:
        argv: Argument list excluding the program name; defaults to
            ``sys.argv[1:]``.

    Returns:
        A process exit code.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        # Force umask 022 for uvctl's own writes (symlinks are exempt, but the
        # ledger and any file we create must stay world-readable even when the
        # caller's umask is 077). The uv subprocess gets its own forced umask.
        os.umask(0o022)
        _maybe_drop_privileges(argv)
        return _dispatch(argv)
    except (
        CliError,
        escalate.EscalationError,
        validate.ValidationError,
        suffix.SuffixError,
    ) as exc:
        print(f"uvctl: error: {exc}", file=sys.stderr)
        return 2


def main_uvxg(argv: list[str] | None = None) -> int:
    """Entry point for the ``uvxg`` read-only companion to ``uvx``.

    Forwards to ``uv tool run`` against the shared dirs and never escalates.

    Args:
        argv: Argument list excluding the program name; defaults to
            ``sys.argv[1:]``.

    Returns:
        A process exit code (only on error; success ``execv``s ``uv``).
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = config_mod.resolve()
    # uvxg never escalates; if it was invoked as root, drop to the service user
    # so the tool does not run as uid 0 — in ANY mode (uvxg needs no root, and
    # this closes the env-induced-system-bin drop-suppression vector).
    if os.geteuid() == 0 and cfg.service_user.value:
        try:
            escalate.drop_privileges_permanently(cfg.service_user.value)
        except escalate.EscalationError as exc:
            print(f"uvxg: error: {exc}", file=sys.stderr)
            return 1
    uv_path = cfg.uv_path.value
    if not uv_path or not os.path.exists(uv_path):
        print("uvxg: error: uv not found; run `uvctl setup`", file=sys.stderr)
        return 1
    env = build_uvxg_env(dict(os.environ), cfg)
    os.execve(uv_path, build_uvxg_argv(uv_path, argv), env)
