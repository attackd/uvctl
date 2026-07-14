"""Unit tests for uvctl.config — resolution precedence + mode detection (tier 1)."""

import os
import pwd

import pytest

from uvctl import config
from uvctl.config import ROOTLESS, SYSTEM_BIN


def _current_username():
    return pwd.getpwuid(os.getuid()).pw_name


# --- resolution precedence: env > file > default -----------------------------


def test_defaults_when_env_and_file_empty():
    cfg = config.resolve(environ={}, file_data={})
    assert cfg.tool_dir.value == "/opt/uv/tools"
    assert cfg.tool_dir.source == "default"
    assert cfg.bin_dir.value == "/opt/uv/bin"
    assert cfg.service_user.value == "uvctl"
    # uv_path has no default
    assert cfg.uv_path.value is None
    assert cfg.uv_path.source == "unset"


def test_file_overrides_default():
    cfg = config.resolve(environ={}, file_data={"tool_dir": "/srv/tools"})
    assert cfg.tool_dir.value == "/srv/tools"
    assert cfg.tool_dir.source == "file"
    # untouched keys still default
    assert cfg.bin_dir.source == "default"


def test_env_overrides_file_and_default():
    cfg = config.resolve(
        environ={"UVCTL_TOOL_DIR": "/env/tools", "UVCTL_TOOL_BIN_DIR": "/env/bin"},
        file_data={"tool_dir": "/srv/tools"},
    )
    assert cfg.tool_dir.value == "/env/tools"
    assert cfg.tool_dir.source == "env:UVCTL_TOOL_DIR"
    assert cfg.bin_dir.value == "/env/bin"
    assert cfg.bin_dir.source == "env:UVCTL_TOOL_BIN_DIR"


def test_empty_env_var_does_not_override():
    # An empty string env var is treated as unset, falling through to file.
    cfg = config.resolve(
        environ={"UVCTL_TOOL_DIR": ""},
        file_data={"tool_dir": "/srv/tools"},
    )
    assert cfg.tool_dir.value == "/srv/tools"
    assert cfg.tool_dir.source == "file"


def test_only_tool_and_bin_have_env_overrides():
    # UVCTL_* overrides exist for tool_dir/bin_dir only; other keys ignore env.
    cfg = config.resolve(
        environ={"UVCTL_CACHE_DIR": "/env/cache"},  # not a recognized override
        file_data={},
    )
    assert cfg.cache_dir.value == "/opt/uv/cache"
    assert cfg.cache_dir.source == "default"


# --- override reporting ------------------------------------------------------


def test_active_env_overrides_lists_only_env_sourced():
    cfg = config.resolve(
        environ={"UVCTL_TOOL_DIR": "/env/tools"},
        file_data={"bin_dir": "/srv/bin"},
    )
    overrides = cfg.active_env_overrides()
    assert [k for k, _ in overrides] == ["tool_dir"]
    assert overrides[0][1].value == "/env/tools"


# --- service-user mode flag --------------------------------------------------


def test_service_user_mode_on_by_default():
    cfg = config.resolve(environ={}, file_data={})
    assert cfg.service_user_mode is True


def test_service_user_mode_off_when_empty():
    cfg = config.resolve(environ={}, file_data={"service_user": ""})
    assert cfg.service_user_mode is False


# --- mode detection ----------------------------------------------------------


@pytest.mark.parametrize(
    ("writable", "expected"),
    [(True, ROOTLESS), (False, SYSTEM_BIN)],
)
def test_detect_mode(writable, expected):
    assert config.detect_mode(writable) == expected


# --- path_writable_by_user ---------------------------------------------------


def test_writable_when_owner_has_write_bit(tmp_path):
    d = tmp_path / "owned"
    d.mkdir(mode=0o700)
    assert config.path_writable_by_user(str(d), _current_username()) is True


def test_not_writable_when_owner_lacks_write_bit(tmp_path):
    d = tmp_path / "readonly"
    d.mkdir()
    d.chmod(0o500)  # r-x, owned by us but no write bit anywhere
    try:
        assert config.path_writable_by_user(str(d), _current_username()) is False
    finally:
        d.chmod(0o700)  # let pytest clean up


def test_writable_when_world_writable(tmp_path):
    d = tmp_path / "worldwritable"
    d.mkdir()
    d.chmod(0o777)
    assert config.path_writable_by_user(str(d), _current_username()) is True


def test_unknown_user_raises(tmp_path):
    with pytest.raises(KeyError):
        config.path_writable_by_user(str(tmp_path), "definitely-no-such-user-xyz")
