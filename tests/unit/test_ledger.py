"""Unit tests for uvctl.ledger — records, attribution, audit log (tier 1)."""

import json
import os
import pwd
import stat

from uvctl import ledger


def _ledger_path(tmp_path):
    return str(tmp_path / "ledger.json")


def _record(**overrides):
    base = dict(
        package="black",
        spec="black==24.4.2",
        suffix="@311",
        mode="rootless",
        executables=[
            {"name": "black", "link": "/opt/uv/bin/black@311", "target": "/s"}
        ],
        scratch_dir="/opt/uv/tools/.suffixed/black@311",
        user="alice",
        timestamp=1_700_000_000.0,
    )
    base.update(overrides)
    return ledger.build_install_record(**base)


# --- attribution -------------------------------------------------------------


def test_invoking_user_prefers_sudo_user():
    assert ledger.invoking_user({"SUDO_USER": "alice"}) == "alice"


def test_invoking_user_falls_back_to_real_uid():
    name = pwd.getpwuid(os.getuid()).pw_name
    assert ledger.invoking_user({}) == name


# --- record / find / remove --------------------------------------------------


def test_load_missing_returns_empty(tmp_path):
    data = ledger.load_ledger(_ledger_path(tmp_path))
    assert data == {"version": ledger.LEDGER_VERSION, "installs": []}


def test_record_install_persists_and_is_findable(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(), path)
    found = ledger.find_active("black", "@311", path)
    assert found is not None
    assert found["spec"] == "black==24.4.2"
    assert found["removed"] is False


def test_record_install_replaces_active_duplicate(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(spec="black==1"), path)
    ledger.record_install(_record(spec="black==2"), path)
    data = ledger.load_ledger(path)
    active = [r for r in data["installs"] if not r["removed"]]
    assert len(active) == 1
    assert active[0]["spec"] == "black==2"


def test_suffix_and_unsuffixed_coexist(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(suffix="@311"), path)
    ledger.record_install(_record(suffix=None), path)
    assert ledger.find_active("black", "@311", path) is not None
    assert ledger.find_active("black", None, path) is not None


def test_mark_removed(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(), path)
    assert ledger.mark_removed("black", "@311", path) is True
    assert ledger.find_active("black", "@311", path) is None


def test_mark_removed_reports_false_when_absent(tmp_path):
    path = _ledger_path(tmp_path)
    assert ledger.mark_removed("nope", "@x", path) is False


def test_removed_entry_is_retained_for_history(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(), path)
    ledger.mark_removed("black", "@311", path)
    data = ledger.load_ledger(path)
    assert len(data["installs"]) == 1  # kept, just flagged
    assert data["installs"][0]["removed"] is True


# --- file mode / atomicity ---------------------------------------------------


def test_ledger_written_mode_644(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(), path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o644


def test_no_temp_file_left_behind(tmp_path):
    path = _ledger_path(tmp_path)
    ledger.record_install(_record(), path)
    leftovers = [p for p in os.listdir(tmp_path) if ".tmp." in p]
    assert leftovers == []


# --- audit log ---------------------------------------------------------------


def test_append_audit_writes_jsonl(tmp_path):
    path = str(tmp_path / "audit.log")
    e1 = ledger.build_audit_entry(
        user="alice",
        mode="rootless",
        command=["uv", "tool", "install", "ruff"],
        outcome="ok",
        timestamp=1.0,
    )
    e2 = ledger.build_audit_entry(
        user="bob",
        mode="system-bin",
        command=["ln", "-s", "a", "b"],
        outcome="failed",
        timestamp=2.0,
    )
    ledger.append_audit(e1, path)
    ledger.append_audit(e2, path)

    lines = [json.loads(x) for x in open(path).read().splitlines()]
    assert [x["user"] for x in lines] == ["alice", "bob"]
    assert lines[0]["command"] == ["uv", "tool", "install", "ruff"]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644


def test_now_is_injectable():
    assert ledger.now(lambda: 42.0) == 42.0


# --- structured audit / syslog mirror ----------------------------------------


def test_format_audit_kv_preserves_insertion_order():
    line = ledger.format_audit_kv(
        {"event": "install", "pkg": "black", "suffix": "@311", "mode": "rootless"}
    )
    assert line == "event=install pkg=black suffix=@311 mode=rootless"


def test_emit_audit_writes_structured_record(tmp_path):
    path = str(tmp_path / "audit.log")
    entry = ledger.emit_audit(
        "install",
        timestamp=1.0,
        user="alice",
        mode="rootless",
        pkg="black",
        suffix="@311",
        outcome="ok",
        path=path,
    )
    assert entry["event"] == "install"
    rec = json.loads(open(path).read().splitlines()[0])
    assert rec["event"] == "install"
    assert rec["pkg"] == "black"
    assert rec["user"] == "alice"


def test_emit_audit_tolerates_unwritable_log(tmp_path):
    # A path under a nonexistent dir makes the file write fail; emit_audit must
    # not raise (the syslog mirror is the trail, and any uid can write it).
    bad = str(tmp_path / "nope" / "audit.log")
    ledger.emit_audit(
        "refused", timestamp=1.0, user="x", mode="system-bin", path=bad
    )  # no raise
