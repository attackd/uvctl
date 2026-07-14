"""Unit tests for uvctl.validate — pure, host-safe (tier 1)."""

import pytest

from uvctl.validate import (
    ValidationError,
    normalize_requirement_name,
    validate_executable_name,
    validate_suffix,
)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("black", "black"),
        ("Black", "black"),
        ("black[d]", "black"),
        ("black==24.4.2", "black"),
        ("black[d]==24.4.2", "black"),
        ("  black >= 1.0 ", "black"),
        ("ruff_lsp", "ruff-lsp"),
        ("Foo.Bar_baz", "foo-bar-baz"),
        ("a--b__c..d", "a-b-c-d"),
    ],
)
def test_normalize_requirement_name(spec, expected):
    assert normalize_requirement_name(spec) == expected


def test_normalize_install_uninstall_roundtrip():
    # install black==24.4.2 --suffix @311 and uninstall black --suffix @311
    # must key to the same normalized name.
    assert normalize_requirement_name("black==24.4.2") == normalize_requirement_name(
        "black"
    )


@pytest.mark.parametrize("spec", ["", "  ", "==1.0", "[extras]"])
def test_normalize_rejects_nameless(spec):
    with pytest.raises(ValidationError):
        normalize_requirement_name(spec)


@pytest.mark.parametrize("name", ["ruff", "black", "semgrep", "black@311", "a.b_c+d-e"])
def test_valid_executable_names(name):
    assert validate_executable_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",  # empty
        "..",  # reserved / traversal
        ".",  # reserved
        "foo/bar",  # path separator
        "foo\\bar",  # windows-style separator
        "../evil",  # traversal
        "-rf",  # leading dash / argv confusion
        "has space",  # whitespace
        "nul\x00byte",  # NUL
        "emoji😀",  # outside charset
    ],
)
def test_invalid_executable_names(name):
    with pytest.raises(ValidationError):
        validate_executable_name(name)


@pytest.mark.parametrize("suffix", ["@311", "_311", "311", "v2-beta"])
def test_valid_suffixes(suffix):
    assert validate_suffix(suffix) == suffix


@pytest.mark.parametrize(
    "suffix",
    [
        "",  # empty
        "a/b",  # path separator
        "..",  # traversal substring
        "x..y",  # traversal substring
        "has space",  # whitespace
        "x" * 33,  # too long
        "bad!",  # outside charset
    ],
)
def test_invalid_suffixes(suffix):
    with pytest.raises(ValidationError):
        validate_suffix(suffix)
