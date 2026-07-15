"""Unit tests for uvctl.snapshot — capture, diff, and the tripwire (tier 1)."""

import os

import pytest

from uvctl import snapshot
from uvctl.snapshot import Snapshot, SnapshotMutationError


def _write(path, data=b"x"):
    with open(path, "wb") as fh:
        fh.write(data)


# --- capture -----------------------------------------------------------------


def test_oversized_file_is_not_hashed(tmp_path, monkeypatch):
    # Files above the cap are recorded (name/size) but not content-hashed, so a
    # giant dropped file can't force unbounded hashing work.
    monkeypatch.setattr(snapshot, "_MAX_HASH_BYTES", 4)
    small = tmp_path / "small"
    small.write_bytes(b"ab")  # <= cap → hashed
    big = tmp_path / "big"
    big.write_bytes(b"abcdefgh")  # > cap → not hashed
    snap = snapshot.Snapshot.capture([str(tmp_path)])
    assert snap.entries[str(small)].sha256 is not None
    assert snap.entries[str(big)].sha256 is None


def test_capture_records_file_symlink_and_kinds(tmp_path):
    _write(tmp_path / "tool", b"binary-contents")
    os.symlink(tmp_path / "tool", tmp_path / "link")

    snap = Snapshot.capture([str(tmp_path)])
    entries = snap.entries
    file_entry = entries[str(tmp_path / "tool")]
    link_entry = entries[str(tmp_path / "link")]

    assert file_entry.kind == "file"
    assert file_entry.sha256 is not None
    assert file_entry.target is None

    assert link_entry.kind == "symlink"
    assert link_entry.sha256 is None
    assert link_entry.target == str(tmp_path / "tool")


def test_capture_skips_missing_roots(tmp_path):
    snap = Snapshot.capture([str(tmp_path / "does-not-exist")])
    assert dict(snap.entries) == {}
    # the requested root is still recorded
    assert snap.roots == (str(tmp_path / "does-not-exist"),)


def test_capture_is_non_recursive(tmp_path):
    (tmp_path / "sub").mkdir()
    _write(tmp_path / "sub" / "deep")
    snap = Snapshot.capture([str(tmp_path)])
    # the subdir is recorded as an entry, but its child is not
    assert str(tmp_path / "sub") in snap.entries
    assert str(tmp_path / "sub" / "deep") not in snap.entries


def test_entries_are_read_only(tmp_path):
    _write(tmp_path / "tool")
    snap = Snapshot.capture([str(tmp_path)])
    with pytest.raises(TypeError):
        snap.entries["/injected"] = object()  # MappingProxyType blocks writes


# --- fingerprint / tripwire --------------------------------------------------


def test_fingerprint_stable_for_unchanged_state(tmp_path):
    _write(tmp_path / "tool")
    a = Snapshot.capture([str(tmp_path)])
    b = Snapshot.capture([str(tmp_path)])
    assert snapshot.fingerprint(a) == snapshot.fingerprint(b)


def test_verify_fingerprint_passes_when_unmutated(tmp_path):
    _write(tmp_path / "tool")
    snap = Snapshot.capture([str(tmp_path)])
    fp = snapshot.fingerprint(snap)
    assert snapshot.verify_fingerprint(snap, fp) == fp


def test_tripwire_fires_on_deliberate_mutation(tmp_path):
    _write(tmp_path / "tool")
    snap = Snapshot.capture([str(tmp_path)])
    fp = snapshot.fingerprint(snap)

    # Simulate a uvctl bug mutating write-once state. Entry is frozen, so this
    # requires bypassing the freeze — exactly the class of bug the tripwire
    # exists to catch.
    victim = next(iter(snap.entries.values()))
    object.__setattr__(victim, "size", victim.size + 1)

    with pytest.raises(SnapshotMutationError):
        snapshot.verify_fingerprint(snap, fp)


# --- diff --------------------------------------------------------------------


def test_diff_detects_addition(tmp_path):
    before = Snapshot.capture([str(tmp_path)])
    _write(tmp_path / "new")
    after = Snapshot.capture([str(tmp_path)])

    changes = snapshot.diff(before, after)
    assert len(changes) == 1
    assert changes[0].kind == "added"
    assert changes[0].path == str(tmp_path / "new")


def test_diff_detects_removal(tmp_path):
    _write(tmp_path / "gone")
    before = Snapshot.capture([str(tmp_path)])
    os.remove(tmp_path / "gone")
    after = Snapshot.capture([str(tmp_path)])

    changes = snapshot.diff(before, after)
    assert [c.kind for c in changes] == ["removed"]


def test_diff_detects_content_modification(tmp_path):
    _write(tmp_path / "f", b"short")
    before = Snapshot.capture([str(tmp_path)])
    _write(tmp_path / "f", b"a much longer body than before")
    after = Snapshot.capture([str(tmp_path)])

    (change,) = snapshot.diff(before, after)
    assert change.kind == "modified"
    assert "sha256" in change.fields
    assert "size" in change.fields


def test_diff_detects_symlink_retarget(tmp_path):
    _write(tmp_path / "a")
    _write(tmp_path / "b")
    os.symlink(tmp_path / "a", tmp_path / "link")
    before = Snapshot.capture([str(tmp_path)])

    os.remove(tmp_path / "link")
    os.symlink(tmp_path / "b", tmp_path / "link")
    after = Snapshot.capture([str(tmp_path)])

    changes = [c for c in snapshot.diff(before, after) if c.path.endswith("/link")]
    assert changes[0].kind == "modified"
    assert "target" in changes[0].fields


def test_diff_empty_when_unchanged(tmp_path):
    _write(tmp_path / "f")
    before = Snapshot.capture([str(tmp_path)])
    after = Snapshot.capture([str(tmp_path)])
    assert snapshot.diff(before, after) == ()


# --- unattributed / report ---------------------------------------------------


def test_unattributed_filters_expected_additions(tmp_path):
    before = Snapshot.capture([str(tmp_path)])
    _write(tmp_path / "intended")
    _write(tmp_path / "surprise")
    after = Snapshot.capture([str(tmp_path)])

    changes = snapshot.diff(before, after)
    leftover = snapshot.unattributed(
        changes, allowed_added=[str(tmp_path / "intended")]
    )
    assert [c.path for c in leftover] == [str(tmp_path / "surprise")]


def test_unattributed_keeps_unexpected_removal_of_allowed_path(tmp_path):
    # An allowed_added path only excuses an *addition*; a removal still surfaces.
    _write(tmp_path / "intended")
    before = Snapshot.capture([str(tmp_path)])
    os.remove(tmp_path / "intended")
    after = Snapshot.capture([str(tmp_path)])

    leftover = snapshot.unattributed(
        snapshot.diff(before, after), allowed_added=[str(tmp_path / "intended")]
    )
    assert [c.kind for c in leftover] == ["removed"]


def test_format_report_language(tmp_path):
    before = Snapshot.capture([str(tmp_path)])
    _write(tmp_path / "x")
    after = Snapshot.capture([str(tmp_path)])
    report = snapshot.format_report(snapshot.diff(before, after))
    assert "not attributable to this install" in report
    assert "tampering" not in report.lower()


def test_format_report_empty():
    assert "No changes" in snapshot.format_report(())


# --- scope_for ---------------------------------------------------------------


def test_scope_for_is_bin_dir_only():
    # Trimmed to bin_dir only: /usr/local/bin is never separately monitored
    # (rootless hooks can't write it; system-bin's bin_dir already is it).
    assert snapshot.scope_for("/opt/uv/bin") == ("/opt/uv/bin",)
    assert snapshot.scope_for("/usr/local/bin") == ("/usr/local/bin",)
