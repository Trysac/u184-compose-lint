# Architecture

`compose-lint` analyzes Docker Compose YAML files by inspecting the YAML Abstract Syntax Tree (AST) constructed via `yaml.compose` using `yaml.SafeLoader`.

## Key Components

1. **Safe Parser & Resource Guard (`linter._parse_yaml_tree`)**:
   - Enforces an input byte size limit.
   - Traverses YAML AST nodes using an explicit stack to enforce depth limits (`max_depth`) and node visit count limits (`max_nodes`), safeguarding against YAML alias bombs (e.g. billion-laughs).
   - Intercepts mapping nodes to detect duplicate mapping keys before standard dictionary conversion drops them (`CL008`).

2. **Rule Evaluator (`linter.lint`)**:
   - Evaluates Compose specification rules (`CL001` through `CL010`).
   - Extracts exact 1-based line numbers directly from AST node marks.
   - Ensures secret values are scrubbed and never included in error messages or reports (`CL005`).

3. **Formatting & CLI (`linter.format_findings` & `__main__.py`)**:
   - Outputs reports in human-readable text (`<filename>:<line> <rule> <severity> <message>`) or JSON.
   - CLI returns 0 on success/warnings, 1 on error-level findings, and 2 on unhandled exceptions or file IO errors.
