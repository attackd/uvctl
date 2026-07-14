"""Privilege transitions.

Trust role: the ONLY module that changes privilege. Runs the ``uv`` subprocess
as the service user (``sudo -u`` or a direct drop when already root/service
user) and, in system-bin mode, escalates to root for the narrow
``ln -s`` / ``rm`` / ledger-write step alone. Escalated subprocesses receive an
explicitly constructed environment (never the caller's, wholesale) with umask
022 forced. ``uvxg``, ``env``, ``run``, ``config``, and ``verify`` never call
into here.

The core security invariant lives here by construction: in service-user mode
the uv subprocess always runs as the service user (via ``sudo -u``, a direct
``setuid`` drop from root, or directly when uvctl already *is* the service
user), never as uid 0. :func:`child_runs_as` exposes that identity so callers
and tests can assert it.
"""

from __future__ import annotations

import os
import pwd
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence

#: Minimal, deterministic PATH handed to every escalated subprocess. Never the
#: caller's PATH: a redirected PATH under sudo is a privilege-escalation vector.
MINIMAL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: umask forced in every escalated/cross-user child, regardless of the caller's
#: umask, so hardened hosts (umask 077) still produce a world-readable tree.
INSTALL_UMASK = 0o022

# Privilege plans returned by :func:`plan_privilege`.
DIRECT = "direct"
ROOT_DROP = "root-drop"
SUDO = "sudo"


class EscalationError(RuntimeError):
    """Raised when a privileged operation cannot be performed safely.

    Covers a missing/unsafe recorded ``uv`` binary and any refusal to proceed
    with an escalated action. Callers translate this into a non-zero exit.
    """


def _current_username() -> str:
    """Return the username of the current effective uid."""
    return pwd.getpwuid(os.geteuid()).pw_name


def build_subprocess_env(
    *,
    tool_dir: str,
    bin_dir: str,
    python_install_dir: str,
    cache_dir: str,
    path: str = MINIMAL_PATH,
) -> dict[str, str]:
    """Construct the explicit environment for an escalated ``uv`` invocation.

    Exactly the variables uvctl intends and nothing inherited implicitly.
    Pinning ``UV_PYTHON_INSTALL_DIR`` is load-bearing: without it uv may place a
    managed Python under the caller's home, and every tool venv would symlink an
    interpreter regular users cannot traverse.

    Args:
        tool_dir: Value for ``UV_TOOL_DIR`` (the scratch tool dir for suffixed
            installs).
        bin_dir: Value for ``UV_TOOL_BIN_DIR``.
        python_install_dir: Value for ``UV_PYTHON_INSTALL_DIR``.
        cache_dir: Value for ``UV_CACHE_DIR``.
        path: Value for ``PATH``; defaults to :data:`MINIMAL_PATH`.

    Returns:
        A fresh environment mapping.
    """
    return {
        "UV_TOOL_DIR": tool_dir,
        "UV_TOOL_BIN_DIR": bin_dir,
        "UV_PYTHON_INSTALL_DIR": python_install_dir,
        "UV_CACHE_DIR": cache_dir,
        "PATH": path,
    }


def check_uv_path(uv_path: str | None, *, allowed_uids: Iterable[int] = (0,)) -> str:
    """Validate the recorded ``uv`` binary before an escalated invocation.

    A user-writable ``uv`` executed by root or the service user is a privilege
    escalation path, so uvctl refuses one. There is no PATH fallback: under
    sudo the result would depend on ``secure_path`` and could differ from what
    the operator tested.

    Args:
        uv_path: The absolute path recorded by ``setup``, or None if unrecorded.
        allowed_uids: Uids permitted to own a writable ``uv`` (default: root
            only). ``setup`` may widen this to the service user's uid.

    Returns:
        ``uv_path`` unchanged, once proven safe.

    Raises:
        EscalationError: If the path is unrecorded, missing, group/world
            writable, or owned-and-writable by a uid outside ``allowed_uids``.
    """
    if not uv_path:
        raise EscalationError("no uv path recorded; run `uvctl setup` to record it")
    if not os.path.exists(uv_path):
        raise EscalationError(
            f"recorded uv path {uv_path!r} no longer exists; re-run `uvctl setup`"
        )
    st = os.stat(uv_path)
    if st.st_mode & 0o022:
        raise EscalationError(
            f"{uv_path!r} is group- or world-writable; refusing to invoke it "
            "under elevated privilege (privilege-escalation risk)"
        )
    if st.st_uid not in set(allowed_uids) and st.st_mode & 0o200:
        raise EscalationError(
            f"{uv_path!r} is owned by a non-trusted account (uid {st.st_uid}) and "
            "writable; refusing to invoke it under elevated privilege"
        )
    return uv_path


def plan_privilege(service_user: str | None, *, current_user: str, euid: int) -> str:
    """Decide how to reach the service user for an escalated action.

    Args:
        service_user: The configured service user, or falsy when service-user
            mode is off (plain operation as the caller).
        current_user: The username uvctl is currently running as.
        euid: The current effective uid.

    Returns:
        :data:`DIRECT` (already the service user, or no service user
        configured), :data:`ROOT_DROP` (running as root, drop via ``setuid``),
        or :data:`SUDO` (running as an unprivileged non-service account).
    """
    if not service_user:
        return DIRECT
    if current_user == service_user:
        return DIRECT
    if euid == 0:
        return ROOT_DROP
    return SUDO


def child_runs_as(plan: str, service_user: str | None, current_user: str) -> str:
    """Return the username the escalated child will run as under ``plan``.

    Instrumentation for the core invariant: in service-user mode this is always
    the service user, never root, for both :data:`SUDO` and :data:`ROOT_DROP`.

    Args:
        plan: A plan from :func:`plan_privilege`.
        service_user: The configured service user.
        current_user: The username uvctl currently runs as.

    Returns:
        The effective username of the child process.
    """
    if plan in (SUDO, ROOT_DROP):
        return service_user  # type: ignore[return-value]
    return current_user


def _umask_preexec(umask: int) -> Callable[[], None]:
    """Return a preexec callable that only forces ``umask`` in the child."""

    def _pre() -> None:
        os.umask(umask)

    return _pre


def _drop_preexec(username: str, umask: int) -> Callable[[], None]:
    """Return a preexec callable that drops to ``username`` and forces ``umask``.

    The user is resolved inside the child (at ``preexec`` time), so constructing
    the callable never requires the account to exist in the parent — important
    for host-side unit tests where the service user is absent.
    """

    def _pre() -> None:
        pw = pwd.getpwnam(username)
        os.initgroups(username, pw.pw_gid)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
        os.umask(umask)

    return _pre


def build_sudo_argv(
    service_user: str,
    env: Mapping[str, str],
    argv: Sequence[str],
) -> list[str]:
    """Build the ``sudo -u <user> env VAR=... <argv>`` command vector.

    Environment variables are passed as separate ``env`` arguments (not through
    a shell), so values containing spaces are safe.

    Args:
        service_user: The account to run as.
        env: The explicit environment to set in the child.
        argv: The command and its arguments.

    Returns:
        The full argument vector to execute.
    """
    assignments = [f"{k}={v}" for k, v in sorted(env.items())]
    return ["sudo", "-u", service_user, "env", *assignments, *argv]


def run_as_service_user(
    argv: Sequence[str],
    *,
    service_user: str | None,
    env: Mapping[str, str] | None = None,
    current_user: str | None = None,
    euid: int | None = None,
    umask: int = INSTALL_UMASK,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
):
    """Run ``argv`` as the service user, choosing sudo / drop / direct.

    Args:
        argv: The command to run (absolute program path expected).
        service_user: The configured service user (falsy → run directly).
        env: Explicit environment for the child; a minimal ``PATH`` is always
            ensured so ``sudo`` itself is resolvable.
        current_user: Override the detected current user (for testing).
        euid: Override the detected effective uid (for testing).
        umask: umask forced in the child (default :data:`INSTALL_UMASK`).
        runner: Injection point for the subprocess runner (defaults to
            :func:`subprocess.run`).

    Returns:
        Whatever ``runner`` returns (a :class:`subprocess.CompletedProcess` for
        the default runner).
    """
    current_user = current_user or _current_username()
    euid = os.geteuid() if euid is None else euid
    plan = plan_privilege(service_user, current_user=current_user, euid=euid)
    child_env = {"PATH": MINIMAL_PATH, **(dict(env) if env else {})}

    if plan == SUDO:
        full = build_sudo_argv(service_user, child_env, argv)  # type: ignore[arg-type]
        return runner(
            full, env={"PATH": MINIMAL_PATH}, preexec_fn=_umask_preexec(umask)
        )
    if plan == ROOT_DROP:
        return runner(
            list(argv),
            env=child_env,
            preexec_fn=_drop_preexec(service_user, umask),  # type: ignore[arg-type]
        )
    return runner(list(argv), env=child_env, preexec_fn=_umask_preexec(umask))


def run_uv(
    uv_args: Sequence[str],
    *,
    uv_path: str,
    tool_dir: str,
    bin_dir: str,
    python_install_dir: str,
    cache_dir: str,
    service_user: str | None,
    allowed_uv_uids: Iterable[int] = (0,),
    current_user: str | None = None,
    euid: int | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
):
    """Validate ``uv`` and run ``uv <uv_args>`` as the service user.

    Args:
        uv_args: Arguments after the ``uv`` program (e.g. ``["tool", "install",
            "ruff"]``).
        uv_path: The recorded absolute ``uv`` path.
        tool_dir: ``UV_TOOL_DIR`` (scratch dir for suffixed installs).
        bin_dir: ``UV_TOOL_BIN_DIR``.
        python_install_dir: ``UV_PYTHON_INSTALL_DIR``.
        cache_dir: ``UV_CACHE_DIR``.
        service_user: The configured service user.
        allowed_uv_uids: Forwarded to :func:`check_uv_path`.
        current_user: Override the detected current user (for testing).
        euid: Override the detected effective uid (for testing).
        runner: Injection point for the subprocess runner.

    Returns:
        Whatever ``runner`` returns.

    Raises:
        EscalationError: If :func:`check_uv_path` rejects ``uv_path``.
    """
    check_uv_path(uv_path, allowed_uids=allowed_uv_uids)
    env = build_subprocess_env(
        tool_dir=tool_dir,
        bin_dir=bin_dir,
        python_install_dir=python_install_dir,
        cache_dir=cache_dir,
    )
    return run_as_service_user(
        [uv_path, *uv_args],
        service_user=service_user,
        env=env,
        current_user=current_user,
        euid=euid,
        runner=runner,
    )


def run_as_root(
    argv: Sequence[str],
    *,
    euid: int | None = None,
    umask: int = INSTALL_UMASK,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
):
    """Run ``argv`` as root — the narrow system-bin symlink/ledger step only.

    Args:
        argv: The command to run.
        euid: Override the detected effective uid (for testing).
        umask: umask forced in the child.
        runner: Injection point for the subprocess runner.

    Returns:
        Whatever ``runner`` returns. When already root, runs directly; otherwise
        prefixes ``sudo``.
    """
    euid = os.geteuid() if euid is None else euid
    child_env = {"PATH": MINIMAL_PATH}
    if euid == 0:
        return runner(list(argv), env=child_env, preexec_fn=_umask_preexec(umask))
    return runner(["sudo", *argv], env=child_env, preexec_fn=_umask_preexec(umask))


def _set_non_dumpable() -> None:
    """Best-effort ``PR_SET_DUMPABLE=0`` to block ptrace/core-dump inspection.

    The kernel already clears the dumpable flag on a credential change, so this
    is defense-in-depth; failure to set it never aborts the drop.
    """
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        _PR_SET_DUMPABLE = 4
        libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:  # noqa: BLE001 - hardening only; kernel already did it
        pass


def drop_privileges_permanently(username: str) -> None:
    """Irrevocably drop the whole process to ``username`` (rootless startup).

    This is the single, permanent privilege transition for rootless mode: after
    it returns, the process cannot hold or regain uid 0. It replaces per-op
    escalation — everything downstream (snapshot, validate, install, symlink,
    ledger) then runs as direct service-user operations.

    The call order is load-bearing: supplementary **groups**, then **gid**, then
    **uid**. After the uid drop the process can no longer change the others, and
    inherited supplementary groups are a residual-privilege leak. ``setresuid``
    sets the **saved** uid to the target too, so re-escalation is impossible;
    the drop is then verified by asserting ``setuid(0)`` fails.

    Args:
        username: The service user to become. Must not be uid 0.

    Raises:
        EscalationError: If not running as root, if ``username`` is uid 0, or if
            the post-drop verification shows the process could regain uid 0.
        OSError: If a credential syscall fails (e.g. the account is unusable).
    """
    if os.geteuid() != 0:
        raise EscalationError("drop_privileges_permanently must be called as root")
    pw = pwd.getpwnam(username)
    uid, gid = pw.pw_uid, pw.pw_gid
    if uid == 0:
        raise EscalationError(f"refusing to 'drop' to a uid-0 account: {username!r}")

    os.initgroups(username, gid)  # groups first
    os.setgid(gid)  # then gid
    if hasattr(os, "setresuid"):
        os.setresuid(uid, uid, uid)  # real = effective = saved (irrevocable)
    else:  # pragma: no cover - macOS fallback; setuid sets saved when privileged
        os.setuid(uid)

    # Verify: with no 0 in the uid set, regaining root must fail.
    try:
        os.setuid(0)
    except (PermissionError, OSError):
        pass
    else:
        raise EscalationError("privilege drop failed: process regained uid 0")

    _set_non_dumpable()
