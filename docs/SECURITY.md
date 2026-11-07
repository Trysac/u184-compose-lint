# Security notes

## Threat model

`compose-lint` acts as a static analysis library processing untrusted YAML input.

### Defended

- **Resource Exhaustion (Billion-Laughs)**: The parser uses an explicit stack, enforcing limits on byte size (`max_bytes`), node visit counts (`max_nodes`), and AST depth (`max_depth`). This prevents recursive depth or alias bomb attacks.
- **Data Exposure**: To prevent leaking credentials, finding messages only name the offending environment key (`CL005`) and the library explicitly strips the content of any environment value before report generation.
- **Unsafe Deserialization**: The library uses `yaml.SafeLoader` to construct the AST, rejecting custom Python object construction.

### Not Defended

- **Logic bypass**: The tool is static; it does not resolve file-system-level includes or environment variable files (`.env`). It cannot detect secret leaks inside files that are not present in the linted text buffer.
