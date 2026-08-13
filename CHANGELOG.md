# Changelog

All notable changes to the standalone WAFstat scanner are documented here.

## [Unreleased]

- Added strict output-schema closure and negative schema tests.
- Removed raw CDN/origin request identifiers and authentication/rate-limit values from persisted response headers.
- Sanitized `www-authenticate` and `retry-after` to presence-only signals so authentication and rate-limit metadata are not retained.
- Narrowed block-like classification to HTTP 403 without the configured challenge indicator or authentication/retry/login response headers; other 4xx/5xx responses are `OTHER` and yield conservative inconclusive results.
- Added response-size and truncation-contract documentation.
- Added CI, CodeQL, Dependabot, contribution, and security-policy scaffolding.
- Separated Semgrep into a hashed optional lock and isolated environment; the default security lock remains Ruff/Bandit/pip-audit only.

## [0.4.0] - Unreleased

- Versioned the classification and output-contract hardening as 0.4.0.
- Added atomic observation writes and bounded response handling from the prior hardening cycle.

## [0.3.0]

- Initial standalone scanner extraction with fixed marker corpus, dry-run plan, same-host redirect default, cross-host opt-in, bodyless marker-safe output, and offline fake-transport tests.
