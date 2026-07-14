"""Configuration resolution and operating-mode detection.

Trust role: reads only; holds no privilege and never writes (``setup`` writes
the config file via its own escalated path). Resolves ``tool_dir`` /
``bin_dir`` / ``service_user`` / ``uv_path`` / ``python_install_dir`` /
``cache_dir`` with precedence env (``UVCTL_TOOL_DIR`` / ``UVCTL_TOOL_BIN_DIR``)
> ``/etc/uvctl/config.toml`` > built-in defaults, tracking where each value
came from so ``config`` and every install/uninstall can print active overrides.

Environment overrides are a documented risk (a user who can influence the
environment of an escalated invocation can redirect writes); surfacing their
source is one of the two required mitigations. The other — constructing the
escalated subprocess environment explicitly — lives in :mod:`uvctl.escalate`.
"""

from __future__ import annotations

import os
import pwd
from dataclasses import dataclass, fields
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.9/3.10 in CI
    import tomli as tomllib

#: Default config file location (root-owned, mode 644; see ``setup``).
DEFAULT_CONFIG_PATH = "/etc/uvctl/config.toml"

#: Built-in defaults. ``uv_path`` has no default: it is recorded by ``setup``.
DEFAULTS: dict[str, str] = {
    "tool_dir": "/opt/uv/tools",
    "bin_dir": "/opt/uv/bin",
    "service_user": "uvctl",
    "python_install_dir": "/opt/uv/python",
    "cache_dir": "/opt/uv/cache",
}

#: The only two settings with environment overrides, and their variable names.
ENV_OVERRIDES: dict[str, str] = {
    "tool_dir": "UVCTL_TOOL_DIR",
    "bin_dir": "UVCTL_TOOL_BIN_DIR",
}

ROOTLESS = "rootless"
SYSTEM_BIN = "system-bin"


@dataclass(frozen=True)
class Setting:
    """A resolved config value together with where it came from.

    Attributes:
        value: The resolved string, or None if unset (e.g. ``uv_path`` before
            ``setup`` records it).
        source: One of ``"env:<VAR>"``, ``"file"``, ``"default"``, or
            ``"unset"``.
    """

    value: str | None
    source: str

    @property
    def from_env(self) -> bool:
        """Whether this value came from an environment override."""
        return self.source.startswith("env:")


@dataclass(frozen=True)
class Config:
    """The fully resolved configuration, one :class:`Setting` per key."""

    tool_dir: Setting
    bin_dir: Setting
    service_user: Setting
    uv_path: Setting
    python_install_dir: Setting
    cache_dir: Setting

    @property
    def service_user_mode(self) -> bool:
        """Whether service-user mode is active (a non-empty service user)."""
        return bool(self.service_user.value)

    def active_env_overrides(self) -> list[tuple[str, Setting]]:
        """Return ``(key, Setting)`` pairs whose value came from the environment.

        Returns:
            The overrides that ``config`` and every install/uninstall must
            print, so a redirected write is always visible.
        """
        return [
            (f.name, getattr(self, f.name))
            for f in fields(self)
            if getattr(self, f.name).from_env
        ]


def load_config_file(path: str = DEFAULT_CONFIG_PATH) -> dict[str, object]:
    """Parse the config TOML, returning an empty mapping if it is absent.

    Args:
        path: Path to the config file.

    Returns:
        The parsed top-level table, or ``{}`` when the file does not exist.

    Raises:
        tomllib.TOMLDecodeError: If the file exists but is not valid TOML.
    """
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("rb") as fh:
        return tomllib.load(fh)


def resolve(
    environ: dict[str, str] | None = None,
    file_data: dict[str, object] | None = None,
) -> Config:
    """Resolve configuration by precedence env > file > default.

    Pure and injectable: pass ``environ`` and ``file_data`` explicitly in
    tests; production callers pass neither and get :data:`os.environ` and the
    parsed :data:`DEFAULT_CONFIG_PATH`.

    Args:
        environ: Environment mapping; defaults to :data:`os.environ`.
        file_data: Parsed config table; defaults to
            :func:`load_config_file`'s result.

    Returns:
        A resolved :class:`Config`.
    """
    env = os.environ if environ is None else environ
    data = load_config_file() if file_data is None else file_data

    def pick(key: str) -> Setting:
        env_var = ENV_OVERRIDES.get(key)
        if env_var and env.get(env_var):
            return Setting(env[env_var], f"env:{env_var}")
        if data.get(key) is not None:
            return Setting(str(data[key]), "file")
        if key in DEFAULTS:
            return Setting(DEFAULTS[key], "default")
        return Setting(None, "unset")

    return Config(**{f.name: pick(f.name) for f in fields(Config)})


def path_writable_by_user(path: str, username: str) -> bool:
    """Report whether ``username`` can write to an existing ``path``.

    Checks the owner/group/other write bits of ``path`` against the user's uid
    and full group set (primary + supplementary). This is the primitive behind
    mode detection: a service-user-writable ``bin_dir`` means rootless mode.

    Args:
        path: An existing filesystem path (typically ``bin_dir``).
        username: The account to test (typically the service user).

    Returns:
        True if the user has write permission on ``path``.

    Raises:
        KeyError: If ``username`` does not exist.
        OSError: If ``path`` cannot be stat-ed.
    """
    st = os.stat(path)
    pw = pwd.getpwnam(username)
    if st.st_uid == pw.pw_uid:
        return bool(st.st_mode & 0o200)
    if st.st_gid in set(os.getgrouplist(username, pw.pw_gid)):
        return bool(st.st_mode & 0o020)
    return bool(st.st_mode & 0o002)


def detect_mode(bin_dir_writable_by_service_user: bool) -> str:
    """Decide the operating mode from ``bin_dir`` writability.

    Args:
        bin_dir_writable_by_service_user: Result of
            :func:`path_writable_by_user` for the effective ``bin_dir`` and the
            configured service user.

    Returns:
        :data:`ROOTLESS` if the service user can write ``bin_dir`` (everything
        runs as the service user), else :data:`SYSTEM_BIN` (only the narrow
        symlink/ledger step escalates to root).
    """
    return ROOTLESS if bin_dir_writable_by_service_user else SYSTEM_BIN
