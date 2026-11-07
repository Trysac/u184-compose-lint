"""CLI interface for compose_lint."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from compose_lint.errors import ComposeLintError
from compose_lint.linter import format_findings, lint


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint.

    Returns 0 if no errors (warnings are permitted),
    1 if any error-level finding exists,
    2 if an IO error or ComposeLintError occurs.
    """
    parser = argparse.ArgumentParser(
        prog="compose-lint",
        description="Lint Docker Compose files with security and correctness rules.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        default=["compose.yaml"],
        help="Compose files to lint (default: compose.yaml)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--disable",
        default="",
        help="Comma-separated list of rule IDs to disable (e.g. CL003,CL009)",
    )

    args = parser.parse_args(argv)

    disable_list = [d.strip() for d in args.disable.split(",") if d.strip()]

    has_errors = False

    for filepath in args.files:
        try:
            with open(filepath, encoding="utf-8") as f:
                content = f.read()
            findings = lint(
                content,
                filename=filepath,
                disable=disable_list,
            )
        except (OSError, ComposeLintError) as exc:
            sys.stderr.write(f"{filepath}: error: {exc}\n")
            return 2

        for finding in findings:
            if finding.severity == "error":
                has_errors = True

        if findings:
            output = format_findings(findings, args.format, filename=filepath)
            if output:
                sys.stdout.write(output + "\n")

    return 1 if has_errors else 0


if __name__ == "__main__":
    sys.exit(main())
