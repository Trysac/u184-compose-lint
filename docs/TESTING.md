# Testing

## Coverage

Tests cover the public API (`lint`, `format_findings`) and the specific acceptance criteria defined in the project specification.

- `tests/test_compose_lint.py`: Contains acceptance tests for rules `CL001` through `CL010`, edge case parsing (such as `input_too_large` or `yaml_error`), and functionality of `format_findings` for text and JSON outputs.

## Policy

- Tests exercise the public API and assert observable outcomes: return values, specific exception codes, and findings.
- Tests are deterministic, avoiding network dependencies or wall-clock dependence.
- Bug fixes are paired with a failing test case that reproduces the issue.