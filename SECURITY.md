# Security Policy

## Supported versions

Only the latest tagged release is considered supported for security fixes.
Development snapshots may change behavior and should not be used as a security
control without review.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in public issues. Report suspected
vulnerabilities privately through GitHub Private Vulnerability Reporting:

https://github.com/tiagokiill/wafstat/security/advisories/new

This reporting path is available because the repository is public. Include:

- affected version or commit;
- exact reproduction steps that do not target third-party systems;
- expected and observed behavior;
- impact assessment; and
- a minimal patch or mitigation, if available.

Do not include credentials, session tokens, customer data, target inventories,
response bodies, or raw marker values in a report. Redact target names and
operational identifiers unless they are necessary to reproduce an issue in an
authorized lab.

The project will validate reports locally and coordinate disclosure with the
reporter when practicable. No testing of systems outside the reporter's
authorized scope is requested or permitted.

Relevant report areas include output leakage, redirect handling, request
bounds, marker handling, schema enforcement, classification safety, and
authorization-scope communication. The scanner does not authorize testing any
target; see `docs/responsible_use.md`.
