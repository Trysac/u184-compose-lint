"""Exception hierarchy for compose_lint."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "input_too_large",
    "yaml_error",
    "invalid_compose",
    "too_deep",
    "too_many_nodes",
    "invalid_option",
]


class ComposeLintError(Exception):
    """Base exception raised by compose_lint with a stable machine-readable code."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        # Ensure messages never echo more than 200 chars of untrusted input
        safe_msg = message[:200] if len(message) > 200 else message
        super().__init__(safe_msg)
        self.code = code
        self.message = safe_msg

    def __repr__(self) -> str:
        return f"ComposeLintError(code={self.code!r}, message={self.message!r})"
