"""Lint docker-compose files with ten security and correctness rules."""

from __future__ import annotations

import logging

from compose_lint.errors import ComposeLintError
from compose_lint.linter import Finding, format_findings, lint

logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"
__all__ = [
    "ComposeLintError",
    "Finding",
    "__version__",
    "format_findings",
    "lint",
]
