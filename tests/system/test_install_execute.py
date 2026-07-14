"""Tier-2 end-to-end: install a real tool and execute it as an unprivileged user.

Uses ``pycowsay`` (pure Python, zero deps, provides a console script) as a tiny,
fast, network-only fixture. Skips cleanly when PyPI is unreachable so the suite
stays green offline; CI (which has network) exercises the real path.

uvctl is invoked as a **subprocess** here, never via in-process ``cli.main`` —
in rootless mode uvctl irrevocably drops the whole process to the service user
at startup, so calling it in-process would drop the pytest process itself. The
subprocess boundary is exactly how the whole-process privilege model is meant
to be used.
"""

import os
import pwd
import socket
import subprocess

import pytest

from uvctl import setup

pytestmark = pytest.mark.system

TESTER = "tester"


def _online():
    try:
        socket.create_connection(("pypi.org", 443), timeout=4).close()
        return True
    except OSError:
        return False


ONLINE = _online()
needs_net = pytest.mark.skipif(
    not ONLINE, reason="no network; real PyPI install skipped"
)


@pytest.fixture(scope="module")
def configured():
    # setup.main does not drop privileges (setup needs root), so calling it
    # in-process is safe.
    assert setup.main([]) == 0
    return True


def _uvctl(*args):
    """Run the uvctl console script as a subprocess (it drops internally)."""
    return subprocess.run(["uvctl", *args], capture_output=True, text=True)


def _run_as_tester(argv):
    """Run argv as the unprivileged tester user, capturing output."""
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


@needs_net
def test_plain_install_then_execute_as_unprivileged_user(configured):
    assert _uvctl("tool", "install", "pycowsay").returncode == 0
    link = "/opt/uv/bin/pycowsay"
    assert os.path.exists(link)
    result = _run_as_tester([link, "moo"])
    assert result.returncode == 0, result.stderr
    assert "moo" in result.stdout


@needs_net
def test_installed_files_owned_by_service_user_not_root(configured):
    # Core invariant: the install ran as the service user, so what it wrote is
    # owned by the service user, never root.
    _uvctl("tool", "install", "pycowsay")
    svc_uid = pwd.getpwnam("uvctl").pw_uid
    link = "/opt/uv/bin/pycowsay"
    assert os.lstat(link).st_uid == svc_uid


@needs_net
def test_suffixed_installs_coexist(configured):
    assert _uvctl("tool", "install", "pycowsay", "--suffix", "@a").returncode == 0
    assert _uvctl("tool", "install", "pycowsay", "--suffix", "@b").returncode == 0
    a = "/opt/uv/bin/pycowsay@a"
    b = "/opt/uv/bin/pycowsay@b"
    assert os.path.islink(a) and os.path.islink(b)
    assert os.path.isabs(os.readlink(a))  # absolute symlinks
    assert _run_as_tester([a, "hi"]).returncode == 0
    assert _run_as_tester([b, "hi"]).returncode == 0


@needs_net
def test_uninstall_suffixed_leaves_siblings(configured):
    _uvctl("tool", "install", "pycowsay", "--suffix", "@a")
    _uvctl("tool", "install", "pycowsay", "--suffix", "@b")
    assert _uvctl("tool", "uninstall", "pycowsay", "--suffix", "@a").returncode == 0
    assert not os.path.lexists("/opt/uv/bin/pycowsay@a")
    assert os.path.lexists("/opt/uv/bin/pycowsay@b")  # sibling untouched


@needs_net
def test_uv_installs_entrypoints_as_symlinks_into_tool_env(configured):
    # The target-based attribution classifier for plain install AND plain
    # uninstall assumes uv links entrypoints as symlinks into the tool env
    # (the uninstall side matches expected deletions by the pre-snapshot's
    # recorded symlink targets). If this assertion ever fails on a new uv, it is
    # the signal to activate the documented by-name fallback (issue 008) — not to
    # "simplify" the assumption away.
    _uvctl("tool", "install", "pycowsay")
    link = "/opt/uv/bin/pycowsay"
    assert os.path.islink(link), (
        "entrypoint is not a symlink; activate by-name fallback"
    )
    assert os.path.realpath(link).startswith("/opt/uv/tools/pycowsay/")


@needs_net
def test_no_verify_rootless_install_succeeds_and_audits_skip(configured):
    result = _uvctl("tool", "install", "pycowsay", "--suffix", "@nv", "--no-verify")
    assert result.returncode == 0, result.stderr
    assert os.path.lexists("/opt/uv/bin/pycowsay@nv")
    audit = open("/var/lib/uvctl/audit.log").read()
    assert "verify_skipped" in audit


def test_uninstall_never_installed_suffix_errors(configured):
    result = _uvctl("tool", "uninstall", "pycowsay", "--suffix", "@never")
    assert result.returncode != 0


def test_suffix_on_wrong_subcommand_is_uvctl_error(configured):
    result = _uvctl("tool", "list", "--suffix", "@x")
    assert result.returncode == 2  # uvctl-side error, not forwarded to uv
