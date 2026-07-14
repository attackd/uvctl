"""Unit tests for uvctl.cli — pure dispatch/helper logic (tier 1)."""

import os

import pytest

from uvctl import cli, ledger
from uvctl import config as config_mod
from uvctl.cli import CliError
from uvctl.validate import ValidationError


def _cfg(**file_data):
    return config_mod.resolve(environ={}, file_data=file_data)


# --- split_suffix ------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected_suffix", "expected_rest"),
    [
        (["tool", "install", "black"], None, ["tool", "install", "black"]),
        (
            ["tool", "install", "black", "--suffix", "@311"],
            "@311",
            ["tool", "install", "black"],
        ),
        (
            ["tool", "install", "black", "--suffix=@311"],
            "@311",
            ["tool", "install", "black"],
        ),
        (
            ["--suffix", "@x", "tool", "install", "black"],
            "@x",
            ["tool", "install", "black"],
        ),
    ],
)
def test_split_suffix(args, expected_suffix, expected_rest):
    suffix, rest = cli.split_suffix(args)
    assert suffix == expected_suffix
    assert rest == expected_rest


def test_split_suffix_missing_value_errors():
    with pytest.raises(CliError):
        cli.split_suffix(["tool", "install", "black", "--suffix"])


# --- is_tool_install_or_uninstall --------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["tool", "install", "x"], True),
        (["tool", "uninstall", "x"], True),
        (["tool", "list"], False),
        (["tool", "upgrade", "x"], False),
        (["pip", "install", "x"], False),
    ],
)
def test_is_tool_install_or_uninstall(args, expected):
    assert cli.is_tool_install_or_uninstall(args) is expected


def test_suffix_on_wrong_subcommand_errors():
    # `uvctl tool list --suffix @x` must be a uvctl-side error, not forwarded.
    with pytest.raises(CliError, match="only supported on tool install/uninstall"):
        cli.cmd_forward(["tool", "list", "--suffix", "@x"], cfg=_cfg())


def test_main_returns_2_on_cli_error():
    assert cli.main(["tool", "list", "--suffix", "@x"]) == 2


# --- resolve_run_target ------------------------------------------------------


def test_resolve_run_target_success(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "semgrep"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)

    target, argv = cli.resolve_run_target(
        str(bin_dir), ["--", "semgrep", "--config", "auto"]
    )
    assert target == str(tool)
    assert argv == ["semgrep", "--config", "auto"]


def test_resolve_run_target_missing_tool_errors(tmp_path):
    with pytest.raises(CliError, match="not installed"):
        cli.resolve_run_target(str(tmp_path), ["--", "ghost"])


def test_resolve_run_target_rejects_path_traversal(tmp_path):
    with pytest.raises(ValidationError):
        cli.resolve_run_target(str(tmp_path), ["--", "../etc/passwd"])


def test_resolve_run_target_requires_a_tool():
    with pytest.raises(CliError):
        cli.resolve_run_target("/opt/uv/bin", ["--"])


# --- verify_ledger -----------------------------------------------------------


def _seed_ledger(tmp_path, link, target):
    path = str(tmp_path / "ledger.json")
    record = ledger.build_install_record(
        package="black",
        spec="black",
        suffix="@311",
        mode="rootless",
        executables=[{"name": "black", "link": str(link), "target": str(target)}],
        user="alice",
        timestamp=1.0,
    )
    ledger.record_install(record, path)
    return path


def test_verify_ledger_healthy(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    link = tmp_path / "link"
    os.symlink(target, link)
    path = _seed_ledger(tmp_path, link, target)
    assert cli.verify_ledger(path) == []


def test_verify_ledger_missing_link(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    path = _seed_ledger(tmp_path, tmp_path / "gone", target)
    problems = cli.verify_ledger(path)
    assert any("missing" in p for p in problems)


def test_verify_ledger_not_a_symlink(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    link = tmp_path / "link"
    link.write_text("not a symlink")  # a regular file where a link is expected
    path = _seed_ledger(tmp_path, link, target)
    assert any("not a symlink" in p for p in cli.verify_ledger(path))


def test_verify_ledger_retargeted(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    other = tmp_path / "other"
    other.write_text("y")
    link = tmp_path / "link"
    os.symlink(other, link)  # points somewhere other than recorded target
    path = _seed_ledger(tmp_path, link, target)
    assert any("retargeted" in p for p in cli.verify_ledger(path))


def test_verify_ledger_ignores_removed(tmp_path):
    target = tmp_path / "real"
    target.write_text("x")
    path = _seed_ledger(tmp_path, tmp_path / "gone", target)
    ledger.mark_removed("black", "@311", path)
    assert cli.verify_ledger(path) == []


# --- format_config -----------------------------------------------------------


def test_format_config_shows_sources_and_mode():
    cfg = config_mod.resolve(
        environ={"UVCTL_TOOL_DIR": "/env/tools"}, file_data={"bin_dir": "/srv/bin"}
    )
    lines = cli.format_config(
        cfg, current_path="/usr/bin:/srv/bin", mode="rootless", mode_reason="writable"
    )
    text = "\n".join(lines)
    assert "tool_dir = /env/tools  [env:UVCTL_TOOL_DIR]" in text
    assert "bin_dir = /srv/bin  [file]" in text
    assert "mode = rootless" in text
    assert "shared bin dir on current PATH: yes" in text
    assert "active environment overrides:" in text


# --- plan_link ---------------------------------------------------------------


def test_plan_link_valid_name(tmp_path):
    link_path, target = cli.plan_link(_cfg(bin_dir=str(tmp_path)), "uvadmin", None)
    assert link_path == str(tmp_path / "uvadmin")
    assert os.path.exists(target)  # resolves to the installed uvctl entry point


def test_plan_link_rejects_bad_name():
    with pytest.raises(ValidationError):
        cli.plan_link(_cfg(), "bad/name", None)


# --- uvxg helpers ------------------------------------------------------------


def test_build_uvxg_argv():
    assert cli.build_uvxg_argv("/opt/uv/bin/uv", ["ruff", "check"]) == [
        "/opt/uv/bin/uv",
        "tool",
        "run",
        "ruff",
        "check",
    ]


def test_build_uvxg_env_overlays_shared_pointers():
    cfg = _cfg()
    env = cli.build_uvxg_env({"HOME": "/home/x"}, cfg)
    assert env["HOME"] == "/home/x"  # caller env preserved
    assert env["UV_TOOL_DIR"] == "/opt/uv/tools"
    assert env["UV_TOOL_BIN_DIR"] == "/opt/uv/bin"


# --- wants_root (--as-root policy) -------------------------------------------


@pytest.mark.parametrize(
    ("argv", "environ", "expected"),
    [
        (["tool", "install", "x"], {}, False),
        (["tool", "install", "x", "--as-root"], {}, True),
        (["tool", "install", "x"], {"UVCTL_ALLOW_ROOT": "1"}, True),
        (["tool", "install", "x"], {"UVCTL_ALLOW_ROOT": "0"}, False),
    ],
)
def test_wants_root(argv, environ, expected):
    assert cli.wants_root(argv, environ) is expected


# --- system-bin front-door gate & --no-verify hard error ---------------------


def test_gate_refuses_system_bin_non_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(CliError, match="requires root"):
        cli._enforce_system_bin_gate("system-bin", _cfg())


def test_gate_noop_in_rootless_and_undetermined(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    cli._enforce_system_bin_gate("rootless", _cfg())  # no raise
    cli._enforce_system_bin_gate(None, _cfg())  # no raise


def test_gate_noop_when_system_bin_and_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cli._enforce_system_bin_gate("system-bin", _cfg())  # root is allowed


def test_no_verify_hard_error_in_system_bin(monkeypatch):
    # Gate passes (root), so we reach the mandatory-integrity refusal.
    monkeypatch.setattr(cli, "_detect_mode", lambda cfg: ("system-bin", "test"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(CliError, match="not available in system-bin"):
        cli.cmd_forward(["tool", "install", "black", "--no-verify"], cfg=_cfg())


# --- _plain_name (attribution anchor for plain installs) ---------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["ruff"], "ruff"),
        (["Ruff_LSP"], "ruff-lsp"),
        (["black==24.4.2"], "black"),
        (["black", "--upgrade"], "black"),
        (["--python", "3.11", "black"], None),  # ambiguous → skip monitoring
        (["--upgrade"], None),  # no package
    ],
)
def test_plain_name(args, expected):
    assert cli._plain_name(args) == expected


# --- should_drop_privileges (whole-process rootless drop) --------------------


def _drop_args(**kw):
    base = dict(
        euid=0,
        is_setup=False,
        as_root=False,
        service_user="uvctl",
        mode="rootless",
    )
    base.update(kw)
    return base


def test_should_drop_in_rootless_root_case():
    assert cli.should_drop_privileges(**_drop_args()) is True


@pytest.mark.parametrize(
    "override",
    [
        {"euid": 1000},  # not root → nothing to drop
        {"is_setup": True},  # setup legitimately needs root
        {"as_root": True},  # explicit root install
        {"service_user": None},  # no service user configured
        {"service_user": ""},
        {"mode": "system-bin"},  # keeps root for the narrow steps
        {"mode": None},  # undetermined (e.g. not set up)
    ],
)
def test_should_not_drop(override):
    assert cli.should_drop_privileges(**_drop_args(**override)) is False
