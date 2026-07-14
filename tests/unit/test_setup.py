"""Unit tests for uvctl.setup pure helpers (tier 1).

Account/dir creation is root-only and tier-2; here we test the config/sudoers
content and the visudo gate with an injected runner.
"""

import argparse

import pytest

from uvctl import config as config_mod
from uvctl import setup
from uvctl.setup import SetupError

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


# --- render_config_toml ------------------------------------------------------


def test_render_config_toml_round_trips():
    text = setup.render_config_toml(
        tool_dir="/opt/uv/tools",
        bin_dir="/opt/uv/bin",
        service_user="uvctl",
        uv_path="/usr/local/bin/uv",
        python_install_dir="/opt/uv/python",
        cache_dir="/opt/uv/cache",
    )
    parsed = tomllib.loads(text)
    assert parsed["tool_dir"] == "/opt/uv/tools"
    assert parsed["service_user"] == "uvctl"
    assert parsed["uv_path"] == "/usr/local/bin/uv"
    assert parsed["cache_dir"] == "/opt/uv/cache"


# --- render_sudoers_fragment -------------------------------------------------


def test_render_sudoers_fragment_shape():
    # Authorizes running uvctl itself as the service user (whole-process model).
    fragment = setup.render_sudoers_fragment(
        "uvctl-admins", "uvctl", "/usr/local/bin/uvctl"
    )
    assert fragment == "%uvctl-admins ALL=(uvctl) NOPASSWD: /usr/local/bin/uvctl *\n"


@pytest.mark.parametrize(
    ("bin_dir", "expected"),
    [
        ("/opt/uv/bin", False),
        ("/usr/local/bin", True),
        ("/usr/bin", True),
        ("/srv/tools/bin", False),
    ],
)
def test_is_system_bin(bin_dir, expected):
    assert setup.is_system_bin(bin_dir) is expected


# --- validate_sudoers --------------------------------------------------------


class _FakeVisudo:
    def __init__(self, returncode, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        return self


def test_validate_sudoers_accepts_valid():
    runner = _FakeVisudo(0)
    ok, _ = setup.validate_sudoers("%g ALL=(u) NOPASSWD: /uv tool *\n", runner=runner)
    assert ok is True
    assert runner.calls[0][:2] == ["visudo", "-cf"]


def test_validate_sudoers_rejects_invalid():
    runner = _FakeVisudo(1, stderr=">>> syntax error")
    ok, message = setup.validate_sudoers("garbage\n", runner=runner)
    assert ok is False
    assert "syntax error" in message


# --- resolve_effective -------------------------------------------------------


def _ns(**kw):
    base = dict(tool_dir=None, bin_dir=None, service_user=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_resolve_effective_defaults():
    cfg = config_mod.resolve(environ={}, file_data={})
    eff = setup.resolve_effective(_ns(), cfg)
    assert eff["tool_dir"] == "/opt/uv/tools"
    assert eff["bin_dir"] == "/opt/uv/bin"
    assert eff["service_user"] == "uvctl"


def test_resolve_effective_flags_override():
    cfg = config_mod.resolve(environ={}, file_data={})
    eff = setup.resolve_effective(
        _ns(tool_dir="/srv/t", bin_dir="/usr/local/bin", service_user="svc"), cfg
    )
    assert eff["tool_dir"] == "/srv/t"
    assert eff["bin_dir"] == "/usr/local/bin"
    assert eff["service_user"] == "svc"


def test_resolve_effective_requires_service_user():
    cfg = config_mod.resolve(environ={}, file_data={"service_user": ""})
    with pytest.raises(SetupError):
        setup.resolve_effective(_ns(), cfg)
