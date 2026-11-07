# Use PyYAML SafeLoader AST inspection for bounded Docker Compose linting

Status: accepted (generated, pending human review)

## Context

Docker Compose files require static security and correctness analysis. Generic YAML parsers discard duplicate keys, discard line numbers upon mapping construction, and are vulnerable to billion-laughs exponential alias expansion. Furthermore, standard logging or error formatting might inadvertently leak plaintext environment credentials.

## Decision

Use `yaml.compose` with `yaml.SafeLoader` to construct an explicit node AST. Traverse the AST iteratively with strict limits on byte count, depth, and node visits to prevent denial of service. Inspect node keys directly to detect duplicate keys (`CL008`), map line numbers from node start marks, and restrict secret rule reporting (`CL005`) strictly to the key identifier without ever printing the sensitive value.

## Consequences

Parsing is safe against malicious inputs and denial of service. Exact line numbers are preserved. Plaintext secrets are never echoed in findings or logs. Third-party dependency is confined strictly to `pyyaml`.
