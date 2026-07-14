"""Unit tests for uvctl.pathmgmt — pure string emitters (tier 1)."""

import pytest

from uvctl import pathmgmt

BIN = "/opt/uv/bin"
TOOL = "/opt/uv/tools"


# --- path_contains: exact-segment matching -----------------------------------


@pytest.mark.parametrize(
    ("path_value", "expected"),
    [
        ("/usr/bin:/opt/uv/bin:/bin", True),
        ("/opt/uv/bin", True),
        ("/bin:/opt/uv/bin", True),
        ("/opt/uv/bin:/bin", True),
        ("", False),
        ("/opt/uv/binary", False),  # neighbor must not match
        ("/opt/uv/bin2:/x", False),
        ("/usr/bin:/bin", False),
    ],
)
def test_path_contains(path_value, expected):
    assert pathmgmt.path_contains(path_value, BIN) is expected


# --- env_path_line: guarded, empty-safe, trailing ----------------------------


def test_env_path_line_guarded_and_trailing():
    line = pathmgmt.env_path_line(BIN)
    assert line == (
        'case ":${PATH}:" in *":/opt/uv/bin:"*) ;; '
        '*) export PATH="${PATH:+${PATH}:}/opt/uv/bin" ;; esac'
    )
    # empty-safe: the ${PATH:+${PATH}:} form prevents a leading empty element.
    assert "${PATH:+${PATH}:}" in line


def test_env_path_line_prepend_form():
    line = pathmgmt.env_path_line(BIN, prepend=True)
    assert 'export PATH="/opt/uv/bin${PATH:+:${PATH}}"' in line
    # still guarded so a double-source cannot duplicate the entry
    assert line.startswith('case ":${PATH}:" in *":/opt/uv/bin:"*) ;;')


# --- env_output: omit-when-present, exports, quoting --------------------------


def test_env_output_includes_path_line_when_absent():
    out = pathmgmt.env_output(BIN, TOOL, current_path="/usr/bin:/bin")
    assert "export PATH=" in out
    assert 'export UV_TOOL_DIR="/opt/uv/tools"' in out
    assert 'export UV_TOOL_BIN_DIR="/opt/uv/bin"' in out
    assert out.endswith("\n")


def test_env_output_omits_path_line_when_present():
    out = pathmgmt.env_output(BIN, TOOL, current_path="/usr/bin:/opt/uv/bin")
    assert "export PATH=" not in out
    # the UV_TOOL_DIR pair is still exported unconditionally
    assert 'export UV_TOOL_DIR="/opt/uv/tools"' in out
    assert 'export UV_TOOL_BIN_DIR="/opt/uv/bin"' in out


def test_env_output_quotes_paths_with_spaces():
    out = pathmgmt.env_output("/opt/uv bin", "/opt/uv tools", current_path="")
    assert 'export UV_TOOL_DIR="/opt/uv tools"' in out
    assert 'export UV_TOOL_BIN_DIR="/opt/uv bin"' in out


def test_env_output_escapes_shell_metacharacters():
    # A path with $ and " must not break out of the double-quoted context.
    out = pathmgmt.env_output('/opt/$x"y', TOOL, current_path="")
    assert r"\$x\"y" in out


# --- cron_path_line: deterministic, shared dir last --------------------------


def test_cron_path_line_deterministic_and_trailing():
    line = pathmgmt.cron_path_line(BIN)
    assert line == (
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/uv/bin"
    )
    # byte-identical regardless of environment; shared dir is last
    assert pathmgmt.cron_path_line(BIN) == line
    assert line.endswith(":/opt/uv/bin")


# --- profile_d_snippet -------------------------------------------------------


def test_profile_d_snippet_is_guarded_static_form():
    snippet = pathmgmt.profile_d_snippet(BIN)
    assert snippet.startswith("# uvctl:")
    assert pathmgmt.env_path_line(BIN) in snippet
    assert snippet.endswith("\n")
