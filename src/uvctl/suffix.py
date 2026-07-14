"""Suffixed side-by-side installs.

Trust role: orchestration; delegates every privilege transition to
:mod:`uvctl.escalate` and every integrity check to :mod:`uvctl.snapshot`.
Installs into a per-suffix scratch tree ``<tool_dir>/.suffixed/<pkg><sfx>`` and
links ``<bin_dir>/<exe><sfx>`` to it. Keys on the PEP 503-normalized package
name so ``install black==24.4.2 --suffix @311`` and a later
``uninstall black --suffix @311`` resolve to the same location. Uninstall
matches symlinks by resolved *target* (inside the scratch dir), never by name,
and every recursive delete passes the deletion guards below.

The pure helpers (``extract_package_spec``, ``scratch_paths``,
``classify_collision``, ``assert_deletion_safe``, ``links_targeting_scratch``)
carry the security-relevant decisions and are unit-tested on the host; the
``install`` / ``uninstall`` orchestrators run subprocesses and mutate the
filesystem and are exercised in the tier-2 container.
"""

from __future__ import annotations

import os
import shutil
import sys

from . import config as config_mod
from . import escalate, ledger, snapshot, validate

SUFFIXED_DIRNAME = ".suffixed"

# Exit codes distinct from uv's, for the integrity-abort paths.
_EXIT_INTEGRITY = 3


class SuffixError(Exception):
    """A user-facing error in the suffixed-install flow (non-zero exit)."""


# --- pure helpers ------------------------------------------------------------


def extract_package_spec(args: list[str]) -> str:
    """Return the requirement spec whose name keys the install.

    ``uv tool install`` takes exactly one package positional. uvctl special-
    cases ``--from`` (whose value *is* the install source) and otherwise skips
    every ``--opt=value`` token and bare flag — deliberately *not* tracking
    which uv options take a separate value, since that knowledge would rot with
    every uv release. Exactly one positional-looking token must remain, or the
    call is refused (fail closed): a space-separated option value like
    ``--python 3.11 black`` would otherwise be misread as the package, keying
    the scratch dir and ledger on the wrong name.

    Args:
        args: The arguments after ``tool install`` / ``tool uninstall`` (with
            ``--suffix`` already stripped upstream).

    Returns:
        The package spec string.

    Raises:
        SuffixError: If no positional package argument is present, or if two or
            more remain (ambiguous — use ``--opt=value`` form).
    """
    positionals: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--from":
            i += 2  # value-taking option: skip the flag and its value
            continue
        if arg.startswith("--from="):
            i += 1
            continue
        if arg.startswith("-"):
            # a bare flag or --opt=value; never a candidate positional
            i += 1
            continue
        positionals.append(arg)
        i += 1
    if not positionals:
        raise SuffixError("no package specified for suffixed install")
    if len(positionals) > 1:
        raise SuffixError(
            "ambiguous arguments: cannot determine the package name from "
            f"{positionals!r}; use --opt=value form (e.g. --python=3.11) for "
            "options that take values when installing with --suffix"
        )
    return positionals[0]


def scratch_paths(tool_dir: str, normalized_name: str, suffix: str) -> tuple[str, str]:
    """Compute the scratch tool dir and scratch bin dir for a suffixed install.

    Args:
        tool_dir: The configured shared tool dir.
        normalized_name: PEP 503-normalized package name.
        suffix: The validated suffix.

    Returns:
        A ``(scratch_tool_dir, scratch_bin_dir)`` pair.
    """
    scratch_tool_dir = os.path.join(
        tool_dir, SUFFIXED_DIRNAME, f"{normalized_name}{suffix}"
    )
    return scratch_tool_dir, os.path.join(scratch_tool_dir, "bin")


def _is_inside(path: str, parent: str) -> bool:
    """Whether ``path`` resolves to ``parent`` or strictly beneath it."""
    parent_real = os.path.realpath(parent)
    real = os.path.realpath(path)
    return real == parent_real or real.startswith(parent_real + os.sep)


def classify_collision(link_path: str, scratch_tool_dir: str, force: bool) -> str:
    """Decide what to do about an existing ``bin_dir`` entry before linking.

    Never uses blind ``ln -sf`` semantics: a foreign file is refused unless
    ``force`` is set.

    Args:
        link_path: The intended ``<bin_dir>/<exe><sfx>`` path.
        scratch_tool_dir: This install's scratch tree.
        force: Whether ``--force`` was requested.

    Returns:
        ``"create"`` (nothing there), ``"skip"`` (already our symlink into this
        scratch tree — idempotent re-run), or ``"replace"`` (foreign, but
        ``force`` allows overwrite).

    Raises:
        SuffixError: If a foreign entry exists and ``force`` is not set.
    """
    if not os.path.lexists(link_path):
        return "create"
    if os.path.islink(link_path) and _is_inside(link_path, scratch_tool_dir):
        return "skip"
    if force:
        return "replace"
    raise SuffixError(
        f"{link_path} already exists and is not managed by this install; "
        "pass --force to overwrite"
    )


def assert_deletion_safe(path: str, tool_dir: str) -> None:
    """Guard a recursive delete: real dir strictly inside ``.suffixed/``.

    Config can change between install and uninstall, so a computed path may not
    be what was installed. Before any recursive delete uvctl asserts the target
    is a real directory strictly within ``<tool_dir>/.suffixed/`` and is not
    itself a symlink.

    Args:
        path: The scratch directory proposed for deletion.
        tool_dir: The configured shared tool dir.

    Raises:
        SuffixError: If the path is a symlink, not a directory, or resolves
            outside ``<tool_dir>/.suffixed/``.
    """
    suffixed_root = os.path.realpath(os.path.join(tool_dir, SUFFIXED_DIRNAME))
    if os.path.islink(path):
        raise SuffixError(f"refusing to delete {path!r}: it is a symlink")
    real = os.path.realpath(path)
    if not os.path.isdir(real):
        raise SuffixError(f"refusing to delete {path!r}: not a directory")
    if not real.startswith(suffixed_root + os.sep):
        raise SuffixError(
            f"refusing to delete {path!r}: resolves to {real!r}, "
            f"outside {suffixed_root!r}"
        )


def links_targeting_scratch(bin_dir: str, scratch_tool_dir: str) -> list[str]:
    """Return ``bin_dir`` symlinks whose target resolves inside a scratch tree.

    Target-based matching (never by name) so an unrelated legitimate file that
    merely shares a name is never removed.

    Args:
        bin_dir: The shared bin directory.
        scratch_tool_dir: The install's scratch tree.

    Returns:
        Absolute paths of matching symlinks, sorted.
    """
    matches: list[str] = []
    if not os.path.isdir(bin_dir):
        return matches
    for entry in os.scandir(bin_dir):
        if entry.is_symlink() and _is_inside(entry.path, scratch_tool_dir):
            matches.append(entry.path)
    return sorted(matches)


def plain_tool_env_dir(tool_dir: str, normalized_name: str) -> str:
    """Return the tool environment dir uv uses for a plain install.

    Args:
        tool_dir: The configured shared tool dir.
        normalized_name: PEP 503-normalized package name.

    Returns:
        ``<tool_dir>/<normalized_name>`` — the attribution anchor for
        target-based classification of plain install/uninstall changes.
    """
    return os.path.join(tool_dir, normalized_name)


def _target_inside(link_path: str, target: str | None, tool_env_dir: str) -> bool:
    """Whether a symlink's recorded target resolves inside ``tool_env_dir``."""
    if target is None:
        return False
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(link_path), target)
    real = os.path.realpath(target)
    env = os.path.realpath(tool_env_dir)
    return real == env or real.startswith(env + os.sep)


def classify_forwarded_changes(changes: tuple, tool_env_dir: str) -> tuple:
    """Return the FINDINGS among plain install/uninstall ``bin_dir`` changes.

    Target-based attribution — no prediction of the package's executable set and
    no receipt parsing. A change is EXPECTED (attributable to this tool) when it
    is a symlink pointing into ``tool_env_dir``:

    - an added or retargeted symlink whose (new) target resolves inside it, or
    - a removed symlink whose (old) target resolved inside it (upgrades and
      ``--force`` legitimately clear stale entrypoints of the same tool).

    Everything else — unattributed creations, unrelated deletions, retargets to
    elsewhere, or content/mode/ownership changes to non-symlinks — is a FINDING.

    Args:
        changes: The result of :func:`uvctl.snapshot.diff` over ``bin_dir``.
        tool_env_dir: The tool's environment dir (see :func:`plain_tool_env_dir`).

    Returns:
        The subset of ``changes`` that are findings.
    """
    findings = []
    for change in changes:
        if change.kind in ("added", "modified"):
            entry = change.after
            attributable = (
                entry is not None
                and entry.kind == "symlink"
                and _target_inside(change.path, entry.target, tool_env_dir)
            )
        elif change.kind == "removed":
            entry = change.before
            attributable = (
                entry is not None
                and entry.kind == "symlink"
                and _target_inside(change.path, entry.target, tool_env_dir)
            )
        else:
            attributable = False
        if not attributable:
            findings.append(change)
    return tuple(findings)


def tool_env_dirs(scratch_tool_dir: str) -> list[str]:
    """Return the uv-created tool environment directory names in a scratch tree.

    Excludes the sibling ``bin`` directory (uv places executables there,
    alongside the environment, because the scratch tool dir and bin dir share a
    parent) and hidden entries. uv names the one remaining directory after the
    normalized package, making it the ground-truth oracle for the parsed name.

    Args:
        scratch_tool_dir: The install's scratch tree.

    Returns:
        Sorted tool environment directory names (normally exactly one).
    """
    if not os.path.isdir(scratch_tool_dir):
        return []
    return sorted(
        e.name
        for e in os.scandir(scratch_tool_dir)
        if e.is_dir() and e.name != "bin" and not e.name.startswith(".")
    )


def assert_name_matches_ground_truth(scratch_tool_dir: str, name: str) -> None:
    """Assert uv's on-disk env dir matches uvctl's parsed/normalized ``name``.

    The pre-linking cross-check: uv's own on-disk behavior is the oracle, so a
    wrong parse can never key the scratch dir and ledger under a bad name. It
    also catches any parsing edge the ambiguity rule did not anticipate.

    Args:
        scratch_tool_dir: The install's scratch tree.
        name: The parsed, PEP 503-normalized package name.

    Raises:
        SuffixError: If the scratch tree does not contain exactly one tool
            environment directory named ``name``.
    """
    found = tool_env_dirs(scratch_tool_dir)
    if found != [name]:
        raise SuffixError(
            f"name cross-check failed: parsed {name!r}, but uv created "
            f"{found} in {scratch_tool_dir}"
        )


# --- orchestration (tier-2) --------------------------------------------------


def _mode(cfg: config_mod.Config) -> str:
    """Detect the operating mode, defaulting to rootless when undetermined."""
    try:
        writable = config_mod.path_writable_by_user(
            cfg.bin_dir.value, cfg.service_user.value
        )
    except (OSError, KeyError, TypeError):
        return config_mod.ROOTLESS
    return config_mod.detect_mode(writable)


def _place_symlink(mode: str, target: str, link_path: str) -> None:
    """Create an absolute symlink, escalating to root only in system-bin mode."""
    if mode == config_mod.SYSTEM_BIN:
        escalate.run_as_root(["ln", "-s", target, link_path])
    else:
        os.symlink(target, link_path)


def _remove_path(mode: str, path: str) -> None:
    """Remove a single path (symlink), escalating to root in system-bin mode."""
    if mode == config_mod.SYSTEM_BIN:
        escalate.run_as_root(["rm", "-f", path])
    else:
        os.remove(path)


def _remove_tree(mode: str, path: str) -> None:
    """Remove a scratch directory tree (guards already checked by the caller)."""
    if mode == config_mod.SYSTEM_BIN:
        escalate.run_as_root(["rm", "-rf", path])
    else:
        shutil.rmtree(path)


def _shadow_warning(link_name: str) -> None:
    """Warn if ``link_name`` shadows something already on the system PATH."""
    existing = shutil.which(link_name)
    if existing:
        print(
            f"uvctl: warning: {link_name} also resolves to {existing} on PATH; "
            "the shared bin dir is appended (trailing), so the system copy wins",
            file=sys.stderr,
        )


def _link_record(name: str, link_path: str, target: str) -> dict[str, str]:
    """Build one executable entry for the ledger."""
    return {"name": name, "link": link_path, "target": target}


def _safe_cleanup_scratch(
    cfg: config_mod.Config, mode: str, scratch_tool_dir: str
) -> None:
    """Remove a scratch install after a pre-linking abort (deletion-guarded)."""
    if not os.path.isdir(scratch_tool_dir):
        return
    try:
        assert_deletion_safe(scratch_tool_dir, cfg.tool_dir.value)
        _remove_tree(mode, scratch_tool_dir)
    except SuffixError as exc:
        print(f"uvctl: could not clean up {scratch_tool_dir}: {exc}", file=sys.stderr)


def _assert_ledger_write_allowed(mode: str) -> None:
    """Tripwire: a system-bin ledger write must happen as root (euid 0).

    Defends against a future refactor that reorders the privilege sequence, in
    the spirit of the snapshot hash tripwire — a self-bug detector, not an
    attacker control.
    """
    if mode == config_mod.SYSTEM_BIN and os.geteuid() != 0:
        raise SuffixError(
            "system-bin ledger write requires euid 0 (privilege-sequence bug)"
        )


def install(
    cfg: config_mod.Config,
    args: list[str],
    suffix: str,
    *,
    no_verify: bool = False,
) -> int:
    """Install ``<pkg>`` into a per-suffix scratch tree and link it into bin_dir.

    Args:
        cfg: The resolved configuration.
        args: Arguments after ``tool install`` (``--suffix`` already stripped).
        suffix: The raw suffix string.
        no_verify: Skip the integrity snapshot machinery. Honored only in
            rootless mode (the CLI rejects it in system-bin before we get here);
            the skip is recorded as an audit event.

    Returns:
        A process exit code (0 on success).
    """
    suffix = validate.validate_suffix(suffix)
    spec = extract_package_spec(args)
    name = validate.normalize_requirement_name(spec)
    force = "--force" in args
    mode = _mode(cfg)
    scratch_tool_dir, scratch_bin_dir = scratch_paths(cfg.tool_dir.value, name, suffix)

    # --no-verify is honored only in rootless mode; when honored, the snapshot
    # machinery is skipped entirely and the skip is recorded.
    verify = not (no_verify and mode == config_mod.ROOTLESS)
    if not verify:
        ledger.emit_audit(
            "verify_skipped",
            timestamp=ledger.now(),
            user=ledger.invoking_user(),
            mode=mode,
            pkg=name,
            suffix=suffix,
        )

    scope = snapshot.scope_for(cfg.bin_dir.value)
    pre = pre_fp = None
    if verify:
        pre = snapshot.Snapshot.capture(scope)
        pre_fp = snapshot.fingerprint(pre)

    result = escalate.run_uv(
        ["tool", "install", *args],
        uv_path=cfg.uv_path.value,
        tool_dir=scratch_tool_dir,
        bin_dir=scratch_bin_dir,
        python_install_dir=cfg.python_install_dir.value,
        cache_dir=cfg.cache_dir.value,
        service_user=cfg.service_user.value,
    )
    if result.returncode != 0:
        print(f"uvctl: uv install failed (exit {result.returncode})", file=sys.stderr)
        return result.returncode

    post = None
    if verify:
        snapshot.verify_fingerprint(pre, pre_fp)
        post = snapshot.Snapshot.capture(scope)
        pkg_changes = snapshot.unattributed(snapshot.diff(pre, post))
        if pkg_changes:
            # Findings abort BEFORE linking, in BOTH modes: fail closed. Nothing
            # is linked or ledgered; the scratch install is cleaned up.
            print(snapshot.format_report(pkg_changes), file=sys.stderr)
            _safe_cleanup_scratch(cfg, mode, scratch_tool_dir)
            ledger.emit_audit(
                "install",
                timestamp=ledger.now(),
                user=ledger.invoking_user(),
                mode=mode,
                pkg=name,
                suffix=suffix,
                outcome="aborted_findings",
            )
            return _EXIT_INTEGRITY

    # Ground-truth cross-check before linking anything: uv's on-disk env dir
    # name must match the parsed name, or we would link/ledger under a bad key.
    try:
        assert_name_matches_ground_truth(scratch_tool_dir, name)
    except SuffixError as exc:
        print(f"uvctl: {exc}; not linking, cleaning up scratch", file=sys.stderr)
        _safe_cleanup_scratch(cfg, mode, scratch_tool_dir)
        return 1

    if not os.path.isdir(scratch_bin_dir):
        print(f"uvctl: uv wrote no executables to {scratch_bin_dir}", file=sys.stderr)
        return 1
    exes = sorted(e.name for e in os.scandir(scratch_bin_dir))
    for exe in exes:
        validate.validate_executable_name(exe)

    links: list[dict[str, str]] = []
    state = ledger.STATE_COMPLETE
    try:
        for exe in exes:
            link_name = f"{exe}{suffix}"
            link_path = os.path.join(cfg.bin_dir.value, link_name)
            target = os.path.join(scratch_bin_dir, exe)
            action = classify_collision(link_path, scratch_tool_dir, force)
            if action == "replace":
                _remove_path(mode, link_path)
            if action != "skip":
                _shadow_warning(link_name)
                _place_symlink(mode, target, link_path)
            links.append(_link_record(link_name, link_path, target))
    except (OSError, escalate.EscalationError) as exc:
        state = ledger.STATE_PARTIAL
        print(f"uvctl: linking incomplete: {exc}", file=sys.stderr)

    if verify:
        final = snapshot.Snapshot.capture(scope)
        leftover = snapshot.unattributed(
            snapshot.diff(post, final), allowed_added=[link["link"] for link in links]
        )
        if leftover:
            print(snapshot.format_report(leftover), file=sys.stderr)
            if mode == config_mod.SYSTEM_BIN:
                return _EXIT_INTEGRITY

    _assert_ledger_write_allowed(mode)
    record = ledger.build_install_record(
        package=name,
        spec=spec,
        suffix=suffix,
        mode=mode,
        executables=links,
        scratch_dir=scratch_tool_dir,
        user=ledger.invoking_user(),
        timestamp=ledger.now(),
        state=state,
    )
    ledger.record_install(record)
    ledger.emit_audit(
        "install",
        timestamp=ledger.now(),
        user=ledger.invoking_user(),
        mode=mode,
        pkg=name,
        suffix=suffix,
        force=force,
        outcome=state,
    )
    for link in links:
        print(f"uvctl: linked {link['link']} -> {link['target']}")
    return 0 if state == ledger.STATE_COMPLETE else 1


def uninstall(cfg: config_mod.Config, args: list[str], suffix: str) -> int:
    """Uninstall a suffixed install and remove its links and scratch tree.

    Args:
        cfg: The resolved configuration.
        args: Arguments after ``tool uninstall`` (``--suffix`` already
            stripped).
        suffix: The raw suffix string.

    Returns:
        A process exit code (0 on success; non-zero if not found).
    """
    suffix = validate.validate_suffix(suffix)
    spec = extract_package_spec(args)
    name = validate.normalize_requirement_name(spec)
    mode = _mode(cfg)
    scratch_tool_dir, scratch_bin_dir = scratch_paths(cfg.tool_dir.value, name, suffix)

    if not os.path.isdir(scratch_tool_dir):
        print(
            f"uvctl: no suffixed install {name}{suffix} found "
            f"(looked in {scratch_tool_dir})",
            file=sys.stderr,
        )
        return 1

    # Inventory the bin_dir symlinks that point into this scratch tree BEFORE
    # running uv uninstall (target-based; reliable even once uv removes files).
    our_links = links_targeting_scratch(cfg.bin_dir.value, scratch_tool_dir)

    result = escalate.run_uv(
        ["tool", "uninstall", name],
        uv_path=cfg.uv_path.value,
        tool_dir=scratch_tool_dir,
        bin_dir=scratch_bin_dir,
        python_install_dir=cfg.python_install_dir.value,
        cache_dir=cfg.cache_dir.value,
        service_user=cfg.service_user.value,
    )
    if result.returncode != 0:
        print(
            f"uvctl: uv uninstall reported exit {result.returncode}; "
            "continuing with link and scratch cleanup",
            file=sys.stderr,
        )

    for link in our_links:
        if os.path.lexists(link):
            _remove_path(mode, link)

    assert_deletion_safe(scratch_tool_dir, cfg.tool_dir.value)
    _remove_tree(mode, scratch_tool_dir)

    _assert_ledger_write_allowed(mode)
    ledger.mark_removed(name, suffix)
    ledger.emit_audit(
        "uninstall",
        timestamp=ledger.now(),
        user=ledger.invoking_user(),
        mode=mode,
        pkg=name,
        suffix=suffix,
        outcome="ok",
    )
    print(f"uvctl: removed suffixed install {name}{suffix} ({len(our_links)} link(s))")
    return 0
