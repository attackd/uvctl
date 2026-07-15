"""``uvctl setup`` — the only phase that legitimately requires root.

Trust role: runs as root and is the sole module permitted to. It creates the
service user and the shared directory tree (owned by the service user), records
the absolute ``uv`` path, writes the root-owned config, ledger dir, and
profile.d snippet, and — only on explicit ``--write-sudoers`` — installs a
``visudo``-validated sudoers fragment. After setup completes, nothing else in
uvctl runs as uid 0 in the default configuration.

The security-relevant *content* (config TOML, sudoers fragment, the
``visudo -cf`` gate) is factored into pure helpers that are unit-tested on the
host; the account/directory mutation runs in the tier-2 container. Setup is
idempotent: a second run with everything already present changes nothing.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable

from . import config as config_mod
from . import pathmgmt

CONFIG_DIR = "/etc/uvctl"
CONFIG_PATH = config_mod.DEFAULT_CONFIG_PATH
PROFILE_D_PATH = "/etc/profile.d/uvctl.sh"
SUDOERS_PATH = "/etc/sudoers.d/uvctl"
LEDGER_DIR = "/var/lib/uvctl"
DEFAULT_ADMIN_GROUP = "uvctl-admins"

_DIR_MODE = 0o755
_CONFIG_MODE = 0o644
_SUDOERS_MODE = 0o440

#: Conservative POSIX-ish name for a user or group. Enforced before a name is
#: interpolated into a sudoers fragment, so a crafted value cannot smuggle in a
#: syntactically-valid-but-broader sudoers rule (``visudo -cf`` checks syntax,
#: not intent).
_PRINCIPAL_NAME = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_-]{0,31}\Z")


def validate_principal_name(name: str, kind: str) -> str:
    """Validate a service-user or admin-group name against a safe charset.

    Args:
        name: The user/group name to check.
        kind: A label for error messages (e.g. ``"service user"``).

    Returns:
        ``name`` unchanged, once proven safe.

    Raises:
        SetupError: If ``name`` is empty or contains characters outside a
            conservative POSIX name charset.
    """
    if not _PRINCIPAL_NAME.match(name):
        raise SetupError(f"unsafe {kind} name: {name!r}")
    return name


#: Root-owned system bin directories that select system-bin mode when chosen as
#: ``bin_dir`` (uvctl must not chown these to the service user).
_SYSTEM_BIN_DIRS = frozenset(
    {
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
    }
)


def is_system_bin(bin_dir: str) -> bool:
    """Whether ``bin_dir`` is a root-owned system location (system-bin mode).

    Args:
        bin_dir: The effective shared bin directory.

    Returns:
        True if ``bin_dir`` is a standard system bin dir, so setup must leave it
        (and the ledger) root-owned rather than handing them to the service
        user.
    """
    return bin_dir in _SYSTEM_BIN_DIRS


class SetupError(Exception):
    """A setup failure; ``main`` prints it and exits non-zero."""


# --- pure helpers ------------------------------------------------------------


def render_config_toml(
    *,
    tool_dir: str,
    bin_dir: str,
    service_user: str,
    uv_path: str,
    python_install_dir: str,
    cache_dir: str,
) -> str:
    """Render the effective settings as ``/etc/uvctl/config.toml`` content.

    Args:
        tool_dir: Shared tool dir.
        bin_dir: Shared bin dir.
        service_user: Service user name.
        uv_path: Recorded absolute ``uv`` path.
        python_install_dir: Pinned ``UV_PYTHON_INSTALL_DIR``.
        cache_dir: Pinned ``UV_CACHE_DIR``.

    Returns:
        TOML text ending in a newline.
    """
    rows = [
        ("tool_dir", tool_dir),
        ("bin_dir", bin_dir),
        ("service_user", service_user),
        ("uv_path", uv_path),
        ("python_install_dir", python_install_dir),
        ("cache_dir", cache_dir),
    ]
    body = "\n".join(f'{key} = "{value}"' for key, value in rows)
    return "# Managed by `uvctl setup`. Edit with care.\n" + body + "\n"


def render_sudoers_fragment(
    admin_group: str, service_user: str, uvctl_path: str
) -> str:
    """Render the opt-in sudoers fragment authorizing ``uvctl`` as the user.

    Under the whole-process privilege model, a limited admin runs
    ``sudo -u <service_user> uvctl ...``; uvctl then starts already as the
    service user (its startup drop is a no-op) and runs directly. So the
    fragment authorizes running the ``uvctl`` executable itself as the service
    user, not ``uv``.

    Args:
        admin_group: The admin group granted access.
        service_user: The account the group may run ``uvctl`` as.
        uvctl_path: The absolute path to the ``uvctl`` executable.

    Returns:
        A single sudoers line ending in a newline.
    """
    return f"%{admin_group} ALL=({service_user}) NOPASSWD: {uvctl_path} *\n"


def validate_sudoers(
    fragment: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> tuple[bool, str]:
    """Validate a sudoers fragment with ``visudo -cf`` before installing it.

    A malformed sudoers fragment can lock out sudo entirely, so this gate is
    mandatory before writing :data:`SUDOERS_PATH`.

    Args:
        fragment: The fragment text to check.
        runner: Injection point for the subprocess runner.

    Returns:
        A ``(ok, message)`` pair; ``ok`` is True only when ``visudo`` accepts
        the fragment.
    """
    fd, tmp = tempfile.mkstemp(prefix="uvctl-sudoers-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(fragment)
        result = runner(["visudo", "-cf", tmp], capture_output=True, text=True)
        message = (result.stderr or result.stdout or "").strip()
        return result.returncode == 0, message
    finally:
        os.remove(tmp)


def resolve_effective(ns: argparse.Namespace, cfg: config_mod.Config) -> dict[str, str]:
    """Overlay CLI flags onto resolved config to get effective setup settings.

    Args:
        ns: Parsed ``setup`` arguments.
        cfg: The already-resolved configuration.

    Returns:
        A mapping of effective ``tool_dir`` / ``bin_dir`` / ``service_user`` /
        ``python_install_dir`` / ``cache_dir``.

    Raises:
        SetupError: If no service user is configured.
    """
    service_user = ns.service_user or cfg.service_user.value
    if not service_user:
        raise SetupError("a service user is required (pass --service-user)")
    validate_principal_name(service_user, "service user")
    return {
        "tool_dir": ns.tool_dir or cfg.tool_dir.value,
        "bin_dir": ns.bin_dir or cfg.bin_dir.value,
        "service_user": service_user,
        "python_install_dir": cfg.python_install_dir.value,
        "cache_dir": cfg.cache_dir.value,
    }


# --- privileged steps (tier-2) -----------------------------------------------


def require_root() -> None:
    """Refuse to proceed unless running as uid 0."""
    if os.geteuid() != 0:
        raise SetupError(
            "setup must run as root; it creates the service user and the "
            "shared directory tree"
        )


def _atomic_write(path: str, content: str, mode: int) -> None:
    """Write ``content`` to ``path`` atomically with ``mode`` (root-owned)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, mode)  # defeat umask on the final mode
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _ensure_service_user(service_user: str) -> None:
    """Create the service user as a system account if absent (idempotent)."""
    try:
        pwd.getpwnam(service_user)
        return
    except KeyError:
        pass
    result = subprocess.run(
        [
            "useradd",
            "--system",
            "--shell",
            "/usr/sbin/nologin",
            "--home-dir",
            "/opt/uv",
            "--no-create-home",
            service_user,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SetupError(f"useradd failed: {result.stderr.strip()}")


def _ensure_dir_owned(path: str, service_user: str, mode: int) -> None:
    """Create ``path`` (if needed) owned by the service user with ``mode``."""
    os.makedirs(path, mode=mode, exist_ok=True)
    pw = pwd.getpwnam(service_user)
    os.chown(path, pw.pw_uid, pw.pw_gid)
    os.chmod(path, mode)


def _ensure_root_dir(path: str, mode: int) -> None:
    """Create ``path`` (if needed) root-owned with ``mode``."""
    os.makedirs(path, mode=mode, exist_ok=True)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def _write_sudoers(admin_group: str, service_user: str, uvctl_path: str) -> None:
    """Validate and install the sudoers fragment (opt-in)."""
    fragment = render_sudoers_fragment(admin_group, service_user, uvctl_path)
    ok, message = validate_sudoers(fragment)
    if not ok:
        raise SetupError(f"refusing to install invalid sudoers fragment: {message}")
    _atomic_write(SUDOERS_PATH, fragment, _SUDOERS_MODE)


def _repair(service_user: str, dirs: list[str]) -> None:
    """Re-chown and re-mode the shared tree to the service user."""
    pw = pwd.getpwnam(service_user)
    for path in dirs:
        if not os.path.isdir(path):
            continue
        for root, subdirs, files in os.walk(path):
            os.chown(root, pw.pw_uid, pw.pw_gid)
            for name in subdirs + files:
                target = os.path.join(root, name)
                if not os.path.islink(target):
                    os.chown(target, pw.pw_uid, pw.pw_gid)
        os.chmod(path, _DIR_MODE)


def main(argv: list[str]) -> int:
    """Run ``uvctl setup``.

    Args:
        argv: Arguments after ``setup``.

    Returns:
        A process exit code.
    """
    parser = argparse.ArgumentParser(prog="uvctl setup")
    parser.add_argument("--tool-dir")
    parser.add_argument("--bin-dir")
    parser.add_argument("--service-user")
    parser.add_argument("--admin-group", default=DEFAULT_ADMIN_GROUP)
    parser.add_argument("--write-sudoers", action="store_true")
    parser.add_argument("--repair", action="store_true")
    ns = parser.parse_args(argv)

    try:
        require_root()
        os.umask(0o022)
        cfg = config_mod.resolve()
        eff = resolve_effective(ns, cfg)
        uv_path = shutil.which("uv") or cfg.uv_path.value
        if not uv_path:
            raise SetupError("could not find `uv` to record; install uv first")
        uv_path = os.path.realpath(uv_path)

        system_bin = is_system_bin(eff["bin_dir"])
        # tool/python/cache are always service-user-owned (uv writes them as the
        # service user). bin_dir is service-user-owned in rootless, but stays
        # root-owned in system-bin mode (the whole reason that mode exists).
        service_owned = [eff["tool_dir"], eff["python_install_dir"], eff["cache_dir"]]

        if ns.repair:
            _repair(eff["service_user"], [*service_owned, eff["bin_dir"]])
            print(f"uvctl setup: repaired ownership/modes for {eff['service_user']}")
            return 0

        _ensure_service_user(eff["service_user"])
        for path in service_owned:
            _ensure_dir_owned(path, eff["service_user"], _DIR_MODE)
        if system_bin:
            _ensure_root_dir(eff["bin_dir"], _DIR_MODE)
        else:
            _ensure_dir_owned(eff["bin_dir"], eff["service_user"], _DIR_MODE)
        _ensure_root_dir(CONFIG_DIR, _DIR_MODE)
        _atomic_write(
            CONFIG_PATH,
            render_config_toml(uv_path=uv_path, **eff),
            _CONFIG_MODE,
        )
        # In rootless mode the whole process runs as the service user after the
        # startup drop, so it must own the ledger dir to write the ledger/audit
        # log. In system-bin mode the ledger write is a narrow root step, so the
        # dir stays root-owned.
        if system_bin:
            _ensure_root_dir(LEDGER_DIR, _DIR_MODE)
        else:
            _ensure_dir_owned(LEDGER_DIR, eff["service_user"], _DIR_MODE)
        _atomic_write(
            PROFILE_D_PATH, pathmgmt.profile_d_snippet(eff["bin_dir"]), _CONFIG_MODE
        )
        if ns.write_sudoers:
            validate_principal_name(ns.admin_group, "admin group")
            _ensure_admin_group(ns.admin_group)
            uvctl_path = os.path.realpath(shutil.which("uvctl") or sys.argv[0])
            _write_sudoers(ns.admin_group, eff["service_user"], uvctl_path)

        _print_summary(eff, uv_path, wrote_sudoers=ns.write_sudoers)
        return 0
    except SetupError as exc:
        print(f"uvctl setup: error: {exc}", file=sys.stderr)
        return 2


def _ensure_admin_group(admin_group: str) -> None:
    """Create the admin group if absent (needed before the sudoers fragment)."""
    try:
        grp.getgrnam(admin_group)
        return
    except KeyError:
        pass
    result = subprocess.run(
        ["groupadd", "--system", admin_group], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SetupError(f"groupadd failed: {result.stderr.strip()}")


def _print_summary(eff: dict[str, str], uv_path: str, *, wrote_sudoers: bool) -> None:
    """Print the post-setup summary, including non-login-context guidance."""
    print("uvctl setup complete:")
    for key in (
        "tool_dir",
        "bin_dir",
        "service_user",
        "python_install_dir",
        "cache_dir",
    ):
        print(f"  {key} = {eff[key]}")
    print(f"  uv_path = {uv_path}")
    print(f"  profile.d snippet: {PROFILE_D_PATH} (new login shells only)")
    print(
        "  existing shells / cron / systemd will NOT see the shared bin dir; "
        f"add it with: {pathmgmt.env_path_line(eff['bin_dir'])}"
    )
    if wrote_sudoers:
        print(f"  sudoers fragment installed: {SUDOERS_PATH}")
