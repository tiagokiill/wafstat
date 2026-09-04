# Changelog

All notable changes to the standalone WAFstat scanner are documented here.

## [Unreleased]

- Prepared a focused public distribution of the standard-library-only scanner.
- Preserved the v0.4 output and classification contract.

## [0.4.0] - Unreleased

- Versioned the classification and output-contract hardening as 0.4.0.
- Added atomic observation writes, bounded response handling, strict output
  schema closure, conservative status handling, and marker-safe metadata.
- Required exact preservation of one decoded probe value at every followed
  redirect hop and rejected invalid redirect port zero before contact.
- Made application-controlled target, request-profile, and observation-write
  errors marker-safe without echoing untrusted values.
- Extended fixed-marker detection through deeper repeated percent encoding so
  nested encodings cannot survive target, User-Agent, or redirect sanitization,
  using fixed-point decoding and fail-closed handling when a defensive decode
  ceiling is hit.
- Limited custom User-Agent values to 512 transport-safe bytes.
- Aligned the published schema with the Latin-1 transport-safe User-Agent
  runtime contract.
- Bound each schema-valid verdict summary to its structured posture and action,
  with regression coverage for all six emitted live combinations.

## [0.3.0]

- Initial standalone scanner extraction with fixed marker corpus, dry-run plan, same-host redirect default, cross-host opt-in, bodyless marker-safe output, and offline fake-transport tests.
