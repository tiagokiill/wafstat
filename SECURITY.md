# Security Policy

## Supported versions

Only the latest tagged release is considered supported for security fixes. Development snapshots may change behavior and should not be used as a security control without review.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues. Until a repository security contact is assigned, report them privately to the project maintainer through the private contact channel associated with the repository account. Include:

- affected version or commit;
- exact reproduction steps that do not target third-party systems;
- expected and observed behavior;
- impact assessment;
- a minimal patch or mitigation if available.

Do not include credentials, session tokens, customer data, raw target inventories, raw response bodies, or raw marker values in a report. Redact target names and operational identifiers unless they are necessary to reproduce the issue in an authorized lab.

The project will acknowledge receipt when practicable, validate the report locally, and coordinate disclosure with the reporter. No live testing of systems outside the reporter's authorized scope is requested or permitted.

## Scope

The public scanner is standard-library-only at runtime and is intended for controlled assessment of owned or explicitly authorized targets. Security reports concerning dependency tooling, output leakage, redirect handling, request bounds, marker handling, schema enforcement, or authorization-scope communication are in scope.

The scanner does not authorize testing of any target. See `docs/responsible_use.md`.
