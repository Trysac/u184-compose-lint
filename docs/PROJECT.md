# Project record

## Objective

Lint docker-compose files with ten security and correctness rules, line numbers from the YAML node tree, bounded parsing and values never echoed.

## Scope

- Parsing and AST inspection of Docker Compose files.
- Ten specific security and correctness rules (CL001-CL010).
- Reporting findings with 1-based line numbers from YAML node marks.
- Bounded parsing (bytes, nodes, depth) to prevent resource exhaustion attacks.
- Safe formatting ensuring sensitive environment values are never included in output.

## Out of Scope

- Running Docker daemons.
- Interpolation of variables from `.env` files.
- Resolution of `extends` or `include` directives.
- Processing profiles.
- Exhaustive schema validation for every possible Compose key.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 2608271 / 17347 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.4610 |

## Factory run u184 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 1889 | 11650 | 0 | 2549 | 0.0226 |
| fix-1 | gemini-3.8-flash | no | 41002 | 1461 | 0 | 102304 | 0.0439 |
| fix-2 | gemini-3.8-flash | no | 34171 | 437 | 0 | 94516 | 0.0344 |
| fix-3 | gemini-3.8-flash | no | 97158 | 988 | 0 | 947115 | 0.1476 |
| fix-4 | gemini-3.8-flash | no | 83476 | 767 | 0 | 670101 | 0.1157 |
| fix-1 | gemini-3.8-flash | no | 33527 | 578 | 0 | 113761 | 0.0358 |
| audit | gemini-3.1-flash-lite | no | 71350 | 291 | 0 | 168811 | 0.0225 |
| docs | gemini-3.1-flash-lite | no | 146541 | 1175 | 0 | 0 | 0.0384 |

Total: $0.4610. Prices: Anthropic list prices.
