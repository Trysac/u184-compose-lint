# compose-lint

[![PyPI version](https://img.shields.io/pypi/v/trysac-compose-lint)](https://pypi.org/project/trysac-compose-lint/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-compose-lint)](LICENSE)
[![CI](https://github.com/Trysac/u184-compose-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u184-compose-lint/actions/workflows/ci.yml)

Lint docker-compose files with ten security and correctness rules, line numbers from the YAML node tree, bounded parsing and values never echoed

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-compose-lint
# or
uv add trysac-compose-lint
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import compose_lint

# normalize() trims surrounding whitespace and lower-cases the text.
print(compose_lint.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    compose_lint.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
