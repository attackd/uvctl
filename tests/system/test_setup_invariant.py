"""Tier-2 system tests: setup end-to-end and the core invariant.

Run ONLY inside the disposable container (root, mutates the host). Proves the
acceptance-checklist items that cannot be checked on a dev host: setup
idempotency, service-user-owned tree, and — the core invariant — that the
escalated install child runs as the service user, never uid 0.
"""

import os
import pwd
import stat
import subprocess

import pytest

from uvctl import config as config_mod
from uvctl import escalate, setup

pytestmark = pytest.mark.system

SERVICE_USER = "uvctl"


def _capturing_runner(argv, **kwargs):
    """A subprocess runner that captures output (for asserting child identity)."""
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


@pytest.fixture(scope="module")
def did_setup():
    """Run `uvctl setup` once as root for the whole module."""
    assert setup.main([]) == 0
    return True


def test_service_user_created(did_setup):
    pwd.getpwnam(SERVICE_USER)  # raises if absent


def test_shared_dirs_owned_by_service_user_mode_755(did_setup):
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    for path in ("/opt/uv/tools", "/opt/uv/bin", "/opt/uv/python", "/opt/uv/cache"):
        st = os.stat(path)
        assert st.st_uid == uid, f"{path} not owned by service user"
        assert stat.S_IMODE(st.st_mode) == 0o755, f"{path} wrong mode"


def test_config_written_root_owned_644(did_setup):
    st = os.stat("/etc/uvctl/config.toml")
    assert st.st_uid == 0
    assert stat.S_IMODE(st.st_mode) == 0o644


def test_profile_d_snippet_written(did_setup):
    content = open("/etc/profile.d/uvctl.sh").read()
    assert "/opt/uv/bin" in content
    assert "case " in content  # guarded static form


def test_ledger_dir_exists(did_setup):
    assert os.path.isdir("/var/lib/uvctl")


def test_setup_is_idempotent(did_setup):
    # A second run with everything present succeeds and changes nothing material.
    before = os.stat("/opt/uv/bin")
    assert setup.main([]) == 0
    after = os.stat("/opt/uv/bin")
    assert (before.st_uid, stat.S_IMODE(before.st_mode)) == (
        after.st_uid,
        stat.S_IMODE(after.st_mode),
    )


def test_detected_mode_is_rootless(did_setup):
    writable = config_mod.path_writable_by_user("/opt/uv/bin", SERVICE_USER)
    assert config_mod.detect_mode(writable) == config_mod.ROOTLESS


def test_core_invariant_child_runs_as_service_user(did_setup):
    # The escalated install child must run as the service user, never root.
    result = escalate.run_as_service_user(
        ["id", "-un"],
        service_user=SERVICE_USER,
        current_user="root",
        euid=0,  # simulate `sudo uvctl`: root drops to the service user
        runner=_capturing_runner,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == SERVICE_USER


def test_escalated_child_uid_is_not_zero(did_setup):
    result = escalate.run_as_service_user(
        ["id", "-u"],
        service_user=SERVICE_USER,
        current_user="root",
        euid=0,
        runner=_capturing_runner,
    )
    assert result.stdout.strip() != "0"


def test_escalated_umask_forced_022(did_setup):
    result = escalate.run_as_service_user(
        ["sh", "-c", "umask"],
        service_user=SERVICE_USER,
        current_user="root",
        euid=0,
        runner=_capturing_runner,
    )
    assert "022" in result.stdout


def test_permanent_drop_is_irrevocable(did_setup):
    """The whole-process rootless drop cannot be reversed (fork'd to be safe)."""
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    pid = os.fork()
    if pid == 0:  # child: mutate credentials here, never in the test process
        try:
            escalate.drop_privileges_permanently(SERVICE_USER)
            assert os.getuid() == uid and os.geteuid() == uid
            # real == effective == saved, so root can never be regained
            assert os.getresuid() == (uid, uid, uid)
            try:
                os.setuid(0)
            except (PermissionError, OSError):
                os._exit(0)  # correct: cannot regain root
            os._exit(3)  # regained root — invariant broken
        except Exception:  # noqa: BLE001
            os._exit(4)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0, f"child exit {os.WEXITSTATUS(status)}"


def test_ledger_dir_writable_by_service_user_in_rootless(did_setup):
    # After the startup drop the process writes the ledger as the service user,
    # so the ledger dir must be service-user-owned in rootless mode.
    st = os.stat("/var/lib/uvctl")
    assert st.st_uid == pwd.getpwnam(SERVICE_USER).pw_uid
