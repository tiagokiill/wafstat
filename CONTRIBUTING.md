# Contributing to WAFstat

## Scope and safety

Contributions must preserve WAFstat's authorized-use, fixed-corpus, bounded-request, no-bypass, and external-observation boundaries. Do not add third-party target lists, credentials, provider automation, raw research observations, or live-target fixtures.

All tests must use injected fake transports. Do not add network calls to unit tests or CI.

## Development

```bash
uv venv .venv
uv pip compile --generate-hashes requirements-dev.in -o requirements-dev.txt
uv pip sync --python .venv/bin/python requirements-dev.txt
make check
```

Ruff, Bandit, and pip-audit are isolated in `.venv-security`; Semgrep is isolated in `.venv-semgrep` because its dependency tree is substantially larger. See `README.md`.

## Change requirements

- Use TDD for behavior changes: write a failing test, observe the failure, implement the smallest fix, and rerun the full suite.
- Update the JSON Schema, generated example, README, responsible-use policy, test plan, and changelog when output or semantics change.
- Bump the tool/schema version for classification or output-contract changes.
- Keep response bodies, raw markers, credentials, and unnecessary request/provider identifiers out of persisted output.
- Run the full offline security gate before requesting review.
- Use focused commits and inspect the staged file list; never use `git add .` in a dirty research worktree.

## Pull requests

Describe the behavior change, tests, security impact, and whether any network/provider activity occurred. Pull requests must not include live-target data or secrets.
