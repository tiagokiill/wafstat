# WAFstat standalone security gate (v0.4 release-candidate review)

Date (UTC): 2026-08-13
Repository: `/home/tk/wafstat` v0.4 release-candidate review
Scope: offline security and contract gate for the dedicated scanner tree
Git state at run: branch `main`, 0 commits, no remote
Network: package-index / advisory lookups for SCA and Semgrep rules only; no WAF target traffic

## Verdict

**Conditional PASS for private local hardening.** The scanner, schema, generated example, test suite, bounded transport path, atomic save path, output-privacy rules, and declared local security environments were exercised offline. **NO-GO for public release** remains appropriate until the first committed tree receives a Git-object secret scan and the repository owner confirms release identity/contact, executes CI/CodeQL on a remote, and performs independent review. No WAF target or provider API was contacted.

| Layer | Pre-hardening | Post-hardening | Blocking for private push? | Blocking for public release? |
|---|---|---|---|---|
| Publication boundary / allowlist | PASS | PASS | No | No |
| Gitleaks secrets (workdir) | PASS (0) | PASS (0) | No | No |
| Gitleaks Git history | N/A | N/A (0 commits) | Re-run after first commit | Yes until clean history scan |
| Project private-term leakage | PASS (0) | PASS (0) | No | No |
| Marker hygiene outside source/tests | PASS | PASS | No | No |
| Offline tests | 56 passed | 88 passed after v0.4 synchronization | No | No |
| Compile / dry-run / schema | PASS | PASS | No | No |
| Bandit medium/high | PASS (0) | PASS (0) | No | No |
| Semgrep python + security-audit | PASS (0) | PASS (0) | No | No |
| Ruff security (production scanner) | 3 findings | PASS (`F,I,B,S` scanner rules) | No | No |
| pip-audit (security lock) | 4 findings (dev-only) | PASS (0 findings) | No | No |
| pip-audit (isolated Semgrep lock) | Not isolated | PASS (0 findings) | No | No |
| Bounded response reads | OPEN | **FIXED** | — | Yes — done |
| Atomic `--save-observations` | OPEN | **FIXED** | — | Yes — done |
| Clean save-error CLI handling | OPEN | **FIXED** | — | Yes — done |
| Ruff nits (unused import, zip strict, B904) | OPEN | **FIXED** | — | Yes — done |

## Hardening changes applied (TDD)

The final offline run used the synchronized v0.4 contract and completed with 88 passing tests.

1. **Bounded response reads (memory-DoS)**
   Added `MAX_RESPONSE_BYTES = 1 MiB` cap and `_bounded_read()` helper in `urllib_transport`. Truncation surfaced honestly as `response_body_truncated` observation warning. Tests: `test_large_response_body_is_truncated_to_cap`, `test_small_response_body_is_not_truncated`.

2. **Atomic `--save-observations` writes (integrity)**
   `_save()` now uses `tempfile.mkstemp` + `os.replace`. No partial files on interrupt/failure; destination only ever contains complete JSON. Tests: `test_save_observations_is_atomic_and_marker_safe`, `test_save_observations_failure_is_clean_cli_error`.

3. **Clean save-error CLI handling**
   `main()` catches `ObservationSaveError`, prints `wafstat error: ...` to stderr, returns `EXIT_SAFETY`. No uncaught tracebacks on unwritable paths.

4. **Response-header privacy tightened**
   `WWW-Authenticate` and `Retry-After` are retained only as the presence marker `[present]`; their authentication/rate-limit values are not persisted.

5. **Ruff nits fixed**
   Removed unused `dataclasses.field` import. `zip(marker_obs, actions, strict=True)`. `raise ... from exc` in atomic-save error path (B904).

The v0.4 contract now includes the conservative block policy identifier `http_403_without_challenge_auth_retry_or_login_header`. The executable, schema, test fixture, and checked-in example are synchronized. `corpus_sha256` is unchanged.

## Tool versions

- Gitleaks 8.30.1, Ruff 0.16.3, Bandit 1.9.4, pip-audit 2.10.1, Semgrep 1.173.0
- Scanner: `wafstat` v0.4; runtime remains standard-library-only.

## Gate results (post-hardening)

```text
compile: PASS
dry-run: PASS (mode=dry-run, network_activity=none, planned_request_count=12)
schema (example + actual dry-run): PASS
gitleaks dir: PASS (0 findings, ~758 KB scanned)
ruff scanner (`F,I,B,S`): PASS
ruff tests/helpers (`F,I,B`): PASS
bandit -ll -ii: PASS (0 medium/high)
semgrep p/python + p/security-audit: PASS (0 findings)
pytest: 88 passed
marker hygiene outside source/tests: PASS
pip-audit security lock: PASS (0 findings)
pip-audit Semgrep lock: PASS (0 findings)
CI action references: immutable commit SHAs verified against intended upstream tags
```

Raw outputs from the final local run were kept outside the candidate tree under `/tmp/wafstat-security-gate-final/`; generated reports are not release artifacts.

## Dependency environment separation

The runtime has no third-party dependencies. `requirements-dev.txt` is the test/schema environment. `requirements-security.txt` contains Ruff, Bandit, and pip-audit and is hashed. `requirements-semgrep.txt` is a separate hashed lock for Semgrep 1.173.0 and its compatible transitive dependencies, including `click 8.4.2` and `mcp 1.29.0`. The security and Semgrep locks each returned `No known vulnerabilities found` under pip-audit.

## SAST inventory and release profiles

Bandit gate (`-ll -ii`): no issues identified; its full JSON inventory recorded 215 LOW-severity issues and zero MEDIUM/HIGH-severity issues. Ruff full inventory (informational, not the release gate): 251 findings, comprising E501=38, S101=211, and S603=2; the release profiles (`F,I,B,S` for `wafstat` and `F,I,B` for tests/helpers) both pass. The retained low-severity Bandit/Ruff findings are test assertions, fixed subprocess calls in tests, and line-length/style findings; no production release-gate finding remains.

## Remaining release gates

The checked-in 26-path candidate consists of the single-file scanner, offline tests, schema/example, release and responsible-use documentation, hashed dependency inputs/locks, the validation script, Makefile, license/citation metadata, and pinned GitHub automation. It contains no target inventory, research observations, provider automation, credentials, run state, or generated caches.

1. The repository still has zero commits; run the Git-object Gitleaks scan after the first local commit.
2. CI and CodeQL workflows are present and action-pinned but have not executed because the repository has no remote.
3. `SECURITY.md` still uses a maintainer/private-contact placeholder until a repository account and contact channel are assigned.
4. Citation metadata contains the confirmed local author identity but intentionally has no invented repository URL or release date.
5. Public visibility and remote creation remain separate owner-approved actions.

## Recommended next actions

Before first remote push (private repo):

1. Create the first local commit from the explicit 26-path scanner-only allowlist.
2. Run `./tools/gitleaks git . --redact` against the new history.

Before public release:

1. Create the first local commit from the explicit scanner-only allowlist.
2. Run the Git-object Gitleaks scan and inspect the committed tree.
3. Create a remote only with explicit approval; execute CI and CodeQL there.
4. Assign the repository security contact and complete citation/repository metadata.
5. Obtain independent review and record candidate checksums.

## What this gate does not prove

- End-to-end behavior against owned live targets
- Statistical repeatability or universal WAF behavior
- Absence of all future dependency advisories
- That AI-assisted review (Codex Security) was performed