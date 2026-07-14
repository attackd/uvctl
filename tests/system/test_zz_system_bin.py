"""Tier-2: system-bin mode end-to-end (issue 007).

Named to sort last: it reconfigures the shared config to ``bin_dir=/usr/local/bin``
(system-bin mode), which must not disturb the rootless tests in other modules.

Uses a **suffixed** install because that is the path where uvctl controls the
linking and performs the narrow root symlink step. Plain installs in system-bin
mode are a separate, documented gap (uv, running as the service user, cannot
link into root-owned ``/usr/local/bin``) — see issue 009.
"""

import os
import pwd
import shutil
import socket
import stat
import subprocess

import pytest

from uvctl import config as config_mod
from uvctl import setup

pytestmark = pytest.mark.system

TESTER = "tester"


def _online():
    try:
        socket.create_connection(("pypi.org", 443), timeout=4).close()
        return True
    except OSError:
        return False


needs_net = pytest.mark.skipif(not _online(), reason="no network; PyPI install skipped")


def _uvctl(*args):
    return subprocess.run(
        [shutil.which("uvctl"), *args], capture_output=True, text=True
    )


def _as_tester(argv):
    pw = pwd.getpwnam(TESTER)

    def drop():
        os.initgroups(TESTER, pw.pw_gid)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    return subprocess.run(
        argv,
        preexec_fn=drop,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )


@pytest.fixture(scope="module")
def system_bin_setup():
    assert setup.main(["--bin-dir", "/usr/local/bin"]) == 0
    return True


def test_setup_keeps_system_bin_and_ledger_root_owned(system_bin_setup):
    # bin_dir stays root-owned in system-bin mode; the tool tree is still the
    # service user's.
    assert os.stat("/usr/local/bin").st_uid == 0
    assert os.stat("/var/lib/uvctl").st_uid == 0
    assert os.stat("/opt/uv/tools").st_uid == pwd.getpwnam("uvctl").pw_uid


def test_detected_mode_is_system_bin(system_bin_setup):
    writable = config_mod.path_writable_by_user("/usr/local/bin", "uvctl")
    assert config_mod.detect_mode(writable) == config_mod.SYSTEM_BIN


@needs_net
def test_suffixed_install_links_into_system_bin_as_root(system_bin_setup):
    result = _uvctl("tool", "install", "pycowsay", "--suffix", "@sys")
    assert result.returncode == 0, result.stderr
    link = "/usr/local/bin/pycowsay@sys"
    assert os.path.islink(link)
    # the narrow symlink step runs as root, so the link is root-owned
    assert os.lstat(link).st_uid == 0
    # a regular user can still run it
    assert _as_tester([link, "hi"]).returncode == 0
    # ledger is root-owned in system-bin mode
    assert os.stat("/var/lib/uvctl/ledger.json").st_uid == 0


@needs_net
def test_suffixed_uninstall_in_system_bin(system_bin_setup):
    _uvctl("tool", "install", "pycowsay", "--suffix", "@sys2")
    assert os.path.islink("/usr/local/bin/pycowsay@sys2")
    result = _uvctl("tool", "uninstall", "pycowsay", "--suffix", "@sys2")
    assert result.returncode == 0, result.stderr
    assert not os.path.lexists("/usr/local/bin/pycowsay@sys2")


def test_symlink_step_mode_755_unaffected(system_bin_setup):
    assert stat.S_IMODE(os.stat("/usr/local/bin").st_mode) & 0o755 == 0o755
