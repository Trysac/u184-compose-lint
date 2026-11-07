# compose-lint

Lint docker-compose files with ten security and correctness rules, line numbers from the YAML node tree, bounded parsing, and values never echoed.

## Installation

```bash
pip install compose-lint
```

## Usage

```python
from compose_lint import lint, format_findings

content = "services:\n  db:\n    image: postgres\n    privileged: true\n"
findings = lint(content)
print(format_findings(findings, "text"))
```

## Rules

- `CL001`: Privileged containers (`privileged: true`)
- `CL002`: Mounting host Docker daemon socket (`docker.sock`)
- `CL003`: Image missing tag, using `:latest`, or lacking digest
- `CL004`: Published port bound without specific host IP
- `CL005`: Plaintext credentials / secrets defined in environment variables
- `CL006`: Host network mode (`network_mode: host`)
- `CL007`: Service depends on undefined service in `depends_on`
- `CL008`: Duplicate mapping keys
- `CL009`: Obsolete top-level `version` key
- `CL010`: Dangerous capabilities added (`ALL` or `SYS_ADMIN` in `cap_add`)

## Why not `docker compose config` or `hadolint`?

`docker compose config` validates basic syntax but ignores common security risks like privileged containers or plaintext secrets. `hadolint` is designed for `Dockerfile` syntax, not the specialized security constraints required for Compose applications.

For security details, see [docs/SECURITY.md](docs/SECURITY.md).