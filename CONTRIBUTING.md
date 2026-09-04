# Contributing to WAFstat

## Scope and safety

Contributions must preserve WAFstat's authorized-use, fixed-corpus,
bounded-request, no-bypass, and external-observation boundaries. Do not add
third-party target lists, credentials, provider automation, raw observations,
or live-target fixtures.

All tests must use injected transports. Do not add network calls to tests or
continuous integration.

## Development

Contributors need Python 3.11 or later and the development dependencies pinned
in `requirements-dev.txt`. Install those dependencies using the environment
and package-management workflow preferred for the platform, then run:

```bash
make check
```

Set `PYTHON` when the preferred interpreter is not the default `python3`, for
example `make PYTHON=python3.12 check`.

## Change requirements

- For behavior changes, write a failing test first and implement the smallest
  change that makes it pass.
- Update the JSON Schema and generated example when the output contract changes.
- Update the README, responsible-use policy, and changelog when user-visible
  behavior or interpretation changes.
- Bump the tool/schema version for classification or output-contract changes.
- Keep response bodies, raw markers, credentials, and unnecessary request or
  provider identifiers out of persisted output.
- Inspect the changed-file list before committing. Do not use broad staging in a
  worktree that contains unrelated research files.

## Pull requests

Describe the behavior change, tests, safety impact, and whether any network or
provider activity occurred. Pull requests must not include live-target data or
secrets.
