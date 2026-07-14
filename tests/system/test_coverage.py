"""Tier-2 coverage for issue 007 acceptance items (rootless).

Runs ONLY in the disposable container. uvctl is invoked as a subprocess (it
drops the whole process to the service user at startup, so in-process calls
would drop pytest itself). ``setup``-only calls are in-process (setup never
drops). Install-based tests are network-gated on PyPI.
"""

import os
import pwd
import shutil
import socket
import stat
import subprocess
import tempfile

import pytest

from uvctl import setup

pytestmark = pytest.mark.system

SVC = "uvctl"
TESTER = "tester"
BIN = "/opt/uv/bin"
FIXTURE = "/app/tests/fixtures/evilfixture"
EVIL = f"{BIN}/evil-dropped"


def _online():
    try:
        socket.create_connection(("pypi.org", 443), timeout=4).close()
        return True
    except OSError:
        return False


needs_net = pytest.mark.skipif(not _online(), reason="no network; PyPI install skipped")


@pytest.fixture(scope="module")
def configured():
    assert setup.main([]) == 0
    return True


def _uvctl_bin():
    return shutil.which("uvctl")


def _uvctl(*args, umask=None, env=None):
    pre = (lambda: os.umask(umask)) if umask is not None else None
    return subprocess.run(
        [_uvctl_bin(), *args], capture_output=True, text=True, preexec_fn=pre, env=env
    )


def _as_tester(argv, env=None):
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
        env=env or {"PATH": "/usr/bin:/bin"},
    )


def _world_readable(path):
    return bool(os.stat(path).st_mode & stat.S_IROTH)


def _stage_fixture():
    """Copy the fixture to a fresh service-user-owned dir and return its path.

    Two reasons: the build runs as the service user and writes ``egg-info`` into
    the source tree (the baked-in copy is root-owned), and a fresh path per call
    forces uv to rebuild — so the build-time hook re-runs and re-drops the file.
    """
    if os.path.lexists(EVIL):
        os.remove(EVIL)  # reset the finding between tests
    pw = pwd.getpwnam(SVC)
    dst = tempfile.mkdtemp(prefix="evilfix-")
    src = os.path.join(dst, "evilfixture")
    shutil.copytree(FIXTURE, src)
    for root, dirs, files in os.walk(dst):
        for name in [root, *(os.path.join(root, f) for f in dirs + files)]:
            os.chown(name, pw.pw_uid, pw.pw_gid)
    return src


# --- setup --repair ----------------------------------------------------------


def test_setup_repair_restores_ownership(configured):
    os.chown(BIN, 0, 0)  # simulate a stray --as-root install
    assert os.stat(BIN).st_uid == 0
    assert setup.main(["--repair"]) == 0
    assert os.stat(BIN).st_uid == pwd.getpwnam(SVC).pw_uid
    assert stat.S_IMODE(os.stat(BIN).st_mode) == 0o755


# --- setup --write-sudoers ---------------------------------------------------


def test_setup_write_sudoers_installs_valid_fragment(configured):
    assert setup.main(["--write-sudoers"]) == 0
    path = "/etc/sudoers.d/uvctl"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o440
    content = open(path).read()
    assert "(uvctl)" in content and "uvctl *" in content
    check = subprocess.run(["visudo", "-cf", path], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


# --- link --------------------------------------------------------------------


def test_link_creates_working_alias(configured):
    assert _uvctl("link", "uvadmin").returncode == 0
    alias = f"{BIN}/uvadmin"
    assert os.path.islink(alias)
    run = subprocess.run(
        [alias, "config"], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}
    )
    assert run.returncode == 0
    assert "uvctl configuration" in run.stdout


# --- uvctl run ---------------------------------------------------------------


def test_run_missing_tool_fails_loudly(configured):
    run = subprocess.run(
        [_uvctl_bin(), "run", "--", "definitely-not-installed"],
        env={},
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0


@needs_net
def test_run_from_empty_environment(configured):
    assert _uvctl("tool", "install", "pycowsay").returncode == 0
    run = subprocess.run(
        [_uvctl_bin(), "run", "--", "pycowsay", "moo"],
        env={},  # empty environment, like a bare cron/systemd context
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    assert "moo" in run.stdout


# --- umask 077 ---------------------------------------------------------------


@needs_net
def test_install_under_umask_077_is_world_readable(configured):
    result = _uvctl("tool", "install", "pycowsay", umask=0o077)
    assert result.returncode == 0, result.stderr
    real = os.path.realpath(f"{BIN}/pycowsay")
    assert _world_readable(real), f"{real} not world-readable under caller umask 077"
    assert os.stat("/opt/uv/tools/pycowsay").st_mode & stat.S_IXOTH


# --- uvxg as a non-root user -------------------------------------------------


@needs_net
def test_uvxg_runs_as_non_root(configured):
    assert _uvctl("tool", "install", "pycowsay").returncode == 0
    result = _as_tester(
        [shutil.which("uvxg"), "pycowsay", "hi"],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert "hi" in result.stdout


# --- interrupted install re-run (idempotency) --------------------------------


@needs_net
def test_interrupted_install_completes_on_rerun(configured):
    assert _uvctl("tool", "install", "pycowsay", "--suffix", "@idem").returncode == 0
    link = f"{BIN}/pycowsay@idem"
    assert os.path.lexists(link)
    os.remove(link)  # simulate a partial install: link missing, scratch intact
    assert _uvctl("tool", "install", "pycowsay", "--suffix", "@idem").returncode == 0
    assert os.path.lexists(link), "identical re-run did not recreate the missing link"


# --- hook-drops-file detection (fixture package) -----------------------------


@needs_net
def test_plain_install_rolls_back_on_hook_drop(configured):
    src = _stage_fixture()
    result = _uvctl("tool", "install", "--from", src, "evilfixture")
    assert result.returncode == 3, (result.returncode, result.stderr)
    assert os.path.lexists(EVIL), "unattributed file was auto-deleted (never-delete)"
    assert not os.path.lexists(f"{BIN}/evilfixture"), "tool was not rolled back"


@needs_net
def test_suffixed_install_aborts_on_hook_drop(configured):
    src = _stage_fixture()
    result = _uvctl("tool", "install", "--from", src, "evilfixture", "--suffix", "@x")
    assert result.returncode == 3, (result.returncode, result.stderr)
    assert os.path.lexists(EVIL), "unattributed file was auto-deleted (never-delete)"
    assert not os.path.lexists(f"{BIN}/evilfixture@x"), "linked despite a finding"
