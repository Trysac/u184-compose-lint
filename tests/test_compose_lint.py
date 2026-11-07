"""Behavior tests for the public API of compose_lint."""

from __future__ import annotations

import pytest

import compose_lint


def test_normalize_trims_and_lowercases() -> None:
    assert compose_lint.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        compose_lint.normalize(value)


def test_version_is_semver() -> None:
    parts = compose_lint.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
