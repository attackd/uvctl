"""Unit tests for uvctl.suffix pure helpers (tier 1).

The install/uninstall orchestrators run subprocesses and are tier-2; here we
test the security-relevant pure decisions: name extraction, scratch layout,
collision handling, deletion guards, and target-based link matching.
"""

import os

import pytest

from uvctl import config as config_mod
from uvctl import snapshot, suffix
from uvctl.suffix import SuffixError

# --- extract_package_spec ----------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["black"], "black"),
        (["black==24.4.2"], "black==24.4.2"),
        (["black[d]"], "black[d]"),
        (["black", "--upgrade"], "black"),
        (["--upgrade", "black"], "black"),
        (["--from", "git+https://x/y", "black"], "black"),
        (["--from=git+https://x/y", "black"], "black"),
        (["--python=3.11", "black"], "black"),  # --opt=value form is unambiguous
    ],
)
def test_extract_package_spec(args, expected):
    assert suffix.extract_package_spec(args) == expected


def test_extract_package_spec_requires_positional():
    with pytest.raises(SuffixError):
        suffix.extract_package_spec(["--upgrade"])


@pytest.mark.parametrize(
    "args",
    [
        ["--python", "3.11", "black"],  # space-separated value misreads as pkg
        ["--index", "https://example/simple", "black"],
        ["black", "ruff"],  # genuinely two positionals
    ],
)
def test_extract_package_spec_refuses_ambiguous(args):
    with pytest.raises(SuffixError, match="ambiguous"):
        suffix.extract_package_spec(args)


# --- scratch_paths -----------------------------------------------------------


def test_scratch_paths():
    tool_dir = "/opt/uv/tools"
    st, sb = suffix.scratch_paths(tool_dir, "black", "@311")
    assert st == "/opt/uv/tools/.suffixed/black@311"
    assert sb == "/opt/uv/tools/.suffixed/black@311/bin"


# --- classify_collision ------------------------------------------------------


def _scratch(tmp_path):
    scratch_tool = tmp_path / "tools" / ".suffixed" / "black@311"
    scratch_bin = scratch_tool / "bin"
    scratch_bin.mkdir(parents=True)
    target = scratch_bin / "black"
    target.write_text("#!/bin/sh\n")
    return str(scratch_tool), str(target)


def test_collision_create_when_absent(tmp_path):
    scratch_tool, _ = _scratch(tmp_path)
    link = str(tmp_path / "bin" / "black@311")
    assert suffix.classify_collision(link, scratch_tool, force=False) == "create"


def test_collision_skip_when_already_ours(tmp_path):
    scratch_tool, target = _scratch(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    link = bin_dir / "black@311"
    os.symlink(target, link)  # our symlink into the scratch tree
    assert suffix.classify_collision(str(link), scratch_tool, force=False) == "skip"


def test_collision_refuses_foreign_file(tmp_path):
    scratch_tool, _ = _scratch(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    foreign = bin_dir / "black@311"
    foreign.write_text("unrelated")
    with pytest.raises(SuffixError, match="--force"):
        suffix.classify_collision(str(foreign), scratch_tool, force=False)


def test_collision_replace_foreign_with_force(tmp_path):
    scratch_tool, _ = _scratch(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    foreign = bin_dir / "black@311"
    foreign.write_text("unrelated")
    assert (
        suffix.classify_collision(str(foreign), scratch_tool, force=True) == "replace"
    )


def test_collision_refuses_foreign_symlink_outside_scratch(tmp_path):
    scratch_tool, _ = _scratch(tmp_path)
    other = tmp_path / "elsewhere"
    other.write_text("x")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    link = bin_dir / "black@311"
    os.symlink(other, link)  # a symlink, but not into our scratch tree
    with pytest.raises(SuffixError):
        suffix.classify_collision(str(link), scratch_tool, force=False)


# --- assert_deletion_safe ----------------------------------------------------


def test_deletion_safe_accepts_real_dir_inside_suffixed(tmp_path):
    tool_dir = tmp_path / "tools"
    scratch = tool_dir / ".suffixed" / "black@311"
    scratch.mkdir(parents=True)
    suffix.assert_deletion_safe(str(scratch), str(tool_dir))  # no raise


def test_deletion_safe_refuses_symlink(tmp_path):
    tool_dir = tmp_path / "tools"
    (tool_dir / ".suffixed").mkdir(parents=True)
    real = tool_dir / ".suffixed" / "real"
    real.mkdir()
    link = tool_dir / ".suffixed" / "black@311"
    os.symlink(real, link)
    with pytest.raises(SuffixError, match="symlink"):
        suffix.assert_deletion_safe(str(link), str(tool_dir))


def test_deletion_safe_refuses_outside_suffixed(tmp_path):
    tool_dir = tmp_path / "tools"
    outside = tool_dir / "not-suffixed"
    outside.mkdir(parents=True)
    with pytest.raises(SuffixError, match="outside"):
        suffix.assert_deletion_safe(str(outside), str(tool_dir))


def test_deletion_safe_refuses_non_directory(tmp_path):
    tool_dir = tmp_path / "tools"
    (tool_dir / ".suffixed").mkdir(parents=True)
    afile = tool_dir / ".suffixed" / "afile"
    afile.write_text("x")
    with pytest.raises(SuffixError, match="not a directory"):
        suffix.assert_deletion_safe(str(afile), str(tool_dir))


def test_deletion_safe_refuses_the_suffixed_root_itself(tmp_path):
    tool_dir = tmp_path / "tools"
    root = tool_dir / ".suffixed"
    root.mkdir(parents=True)
    # the .suffixed root is not "strictly inside" itself
    with pytest.raises(SuffixError):
        suffix.assert_deletion_safe(str(root), str(tool_dir))


# --- links_targeting_scratch -------------------------------------------------


def test_links_targeting_scratch_matches_by_target(tmp_path):
    tool_dir = tmp_path / "tools"
    scratch_bin = tool_dir / ".suffixed" / "black@311" / "bin"
    scratch_bin.mkdir(parents=True)
    scratch_tool = tool_dir / ".suffixed" / "black@311"
    (scratch_bin / "black").write_text("#!/bin/sh\n")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # a matching link into the scratch tree
    os.symlink(scratch_bin / "black", bin_dir / "black@311")
    # an unrelated symlink pointing elsewhere
    other = tmp_path / "other"
    other.write_text("x")
    os.symlink(other, bin_dir / "unrelated")
    # a plain file with a colliding-looking name
    (bin_dir / "black@312").write_text("not a link")

    matches = suffix.links_targeting_scratch(str(bin_dir), str(scratch_tool))
    assert matches == [str(bin_dir / "black@311")]


def test_links_targeting_scratch_empty_when_bin_dir_missing(tmp_path):
    assert suffix.links_targeting_scratch(str(tmp_path / "nope"), str(tmp_path)) == []


# --- name cross-check (ground truth) -----------------------------------------


def _scratch_with_env(tmp_path, env_name):
    scratch = tmp_path / ".suffixed" / "black@311"
    (scratch / env_name).mkdir(parents=True)
    (scratch / "bin").mkdir()  # uv places executables alongside the env
    (scratch / ".hidden").mkdir()  # ignored
    return str(scratch)


def test_tool_env_dirs_excludes_bin_and_hidden(tmp_path):
    scratch = _scratch_with_env(tmp_path, "black")
    assert suffix.tool_env_dirs(scratch) == ["black"]


def test_tool_env_dirs_empty_when_missing(tmp_path):
    assert suffix.tool_env_dirs(str(tmp_path / "nope")) == []


def test_name_cross_check_passes_on_match(tmp_path):
    scratch = _scratch_with_env(tmp_path, "black")
    suffix.assert_name_matches_ground_truth(scratch, "black")  # no raise


def test_name_cross_check_fails_on_mismatch(tmp_path):
    # uv created an env dir named other than the parsed name → abort.
    scratch = _scratch_with_env(tmp_path, "notblack")
    with pytest.raises(SuffixError, match="cross-check failed"):
        suffix.assert_name_matches_ground_truth(scratch, "black")


def test_name_cross_check_fails_on_extra_env_dir(tmp_path):
    scratch = _scratch_with_env(tmp_path, "black")
    (tmp_path / ".suffixed" / "black@311" / "sneaky").mkdir()
    with pytest.raises(SuffixError):
        suffix.assert_name_matches_ground_truth(scratch, "black")


# --- system-bin ledger-write tripwire ----------------------------------------


def test_ledger_write_tripwire_refuses_system_bin_non_root(monkeypatch):
    monkeypatch.setattr(suffix.os, "geteuid", lambda: 1000)
    with pytest.raises(SuffixError, match="euid 0"):
        suffix._assert_ledger_write_allowed(config_mod.SYSTEM_BIN)


def test_ledger_write_tripwire_allows_rootless(monkeypatch):
    monkeypatch.setattr(suffix.os, "geteuid", lambda: 1000)
    suffix._assert_ledger_write_allowed(config_mod.ROOTLESS)  # no raise


def test_ledger_write_tripwire_allows_system_bin_root(monkeypatch):
    monkeypatch.setattr(suffix.os, "geteuid", lambda: 0)
    suffix._assert_ledger_write_allowed(config_mod.SYSTEM_BIN)  # no raise


# --- plain-install target-based attribution ----------------------------------


def test_plain_tool_env_dir():
    assert suffix.plain_tool_env_dir("/opt/uv/tools", "black") == "/opt/uv/tools/black"


def _plain_setup(tmp_path, exe="black"):
    """Return (bin_dir, env_dir, exe_target) for a uv-style plain install."""
    env_bin = tmp_path / "tools" / "black" / "bin"
    env_bin.mkdir(parents=True)
    target = env_bin / exe
    target.write_text("#!/bin/sh\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    return bin_dir, str(tmp_path / "tools" / "black"), target


def test_classify_expected_symlink_into_env(tmp_path):
    bin_dir, env_dir, target = _plain_setup(tmp_path)
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    os.symlink(target, bin_dir / "black")  # uv links the entrypoint into the env
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert findings == ()


def test_classify_finding_unrelated_dropped_file(tmp_path):
    bin_dir, env_dir, _ = _plain_setup(tmp_path)
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    (bin_dir / "evil").write_text("dropped by a hook")  # not a symlink into env
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert [c.path for c in findings] == [str(bin_dir / "evil")]


def test_classify_finding_symlink_to_elsewhere(tmp_path):
    bin_dir, env_dir, _ = _plain_setup(tmp_path)
    other = tmp_path / "elsewhere"
    other.write_text("x")
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    os.symlink(other, bin_dir / "black")  # a symlink, but not into the tool env
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert len(findings) == 1


def test_classify_expected_removed_entrypoint(tmp_path):
    # An upgrade/uninstall removing an entrypoint that resolved into the env is
    # expected, not a finding.
    bin_dir, env_dir, target = _plain_setup(tmp_path)
    os.symlink(target, bin_dir / "black")
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    os.remove(bin_dir / "black")
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert findings == ()


def test_classify_finding_planted_symlink_wrong_name(tmp_path):
    # A hook plants a symlink into the tool env under an ARBITRARY name (kubectl
    # -> env/bin/black). It resolves inside the env, but the name doesn't match
    # the entrypoint it points at, so it must be a finding, not "expected".
    bin_dir, env_dir, target = _plain_setup(tmp_path)  # target = env/bin/black
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    os.symlink(target, bin_dir / "kubectl")  # name/target mismatch
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert [os.path.basename(c.path) for c in findings] == ["kubectl"]


def test_classify_finding_symlink_into_env_but_not_bin(tmp_path):
    # A symlink resolving into the env but NOT the canonical <env>/bin/<name>
    # entrypoint is a finding.
    bin_dir, env_dir, _ = _plain_setup(tmp_path)
    stray = tmp_path / "tools" / "black" / "lib" / "evil"
    stray.parent.mkdir(parents=True)
    stray.write_text("x")
    pre = snapshot.Snapshot.capture([str(bin_dir)])
    os.symlink(stray, bin_dir / "black")
    post = snapshot.Snapshot.capture([str(bin_dir)])
    findings = suffix.classify_forwarded_changes(snapshot.diff(pre, post), env_dir)
    assert len(findings) == 1
