# WAFstat Public Scanner Test Plan

Date: 2026-08-13
Artifact under test: `./wafstat` v0.4
Test implementation: `tests/test_public_wafstat_scanner.py`

## Objective

Validate that the public single-file WAFstat scanner behaves as a safe, conservative, reproducible external enforcement-verification tool.

The test plan prioritizes the following properties:

1. `scan HOST` is the deliberate live operation.
2. `--dry-run` is the explicit no-network planning mode.
3. The request profile is stable and auditable.
4. URL and User-Agent validation reject unsafe input.
5. Redirect handling is bounded and marker-safe.
6. Classification underclaims ambiguous evidence.
7. Runtime failures are never treated as enforcement.
8. Saved output is bodyless and raw-marker-safe.
9. Tests use fake/injected transports and never perform real network activity.
10. Public classification requires no expected label, provider API, origin logs, or private configuration.
11. Heterogeneous block/challenge enforcement and partial enforcement remain explainable without exposing marker values.

## Scope

In scope:

- CLI parsing and safety gates.
- Dry-run rendering and JSON output.
- Request profile construction.
- Target normalization and validation.
- Redirect-following behavior using fake transports.
- Same-shape benign baseline behavior.
- Marker probe classification using fake transports.
- Verdict rendering and JSON serialization.
- Saved observation hygiene.
- Marker leakage guards.

Out of scope for this offline test plan:

- Live HTTP validation against WAFSTAT targets.
- Cloudflare or ModSecurity configuration changes.
- Firewall/DNS/WAF/provider API changes.
- Payload mutation, bypass testing, fuzzing, crawling, or target discovery.
- Performance benchmarking beyond local test execution.

Any live validation requires a separate user-approved run plan.

## Test environment

Expected local environment:

```bash
cd /home/tk/wafstat
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
python3 -m compileall wafstat tests/test_public_wafstat_scanner.py
```

Full standalone regression command:

```bash
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
.venv/bin/python -m py_compile wafstat tests/test_public_wafstat_scanner.py scripts/validate_examples.py
.venv/bin/python scripts/validate_examples.py
```

No test should call the real `urllib_transport` path. Tests should inject fake transport callables.

## Test cases

| ID | Area | Scenario | Expected result |
|---|---|---|---|
| PS-001 | Dry-run safety | `wafstat scan example.com --dry-run` with injected failing transport | Exit 0; no transport call; output includes `network_activity: none`; no raw marker values. |
| PS-002 | Dry-run CLI | Subprocess dry-run with `--dry-run` | Exit 0; planned logical request count 12; maximum transport requests 72; no raw marker values. |
| PS-003 | Live fake execution | Bare `scan HOST --json` with fake 200 transport | 12 fake calls; exit 0; stdout remains parseable JSON; authorization notice is on stderr. |
| PS-004 | Removed flag | `--execute` | Argparse exit 2 before transport. |
| PS-005 | Removed flag | `--i-have-authorization` | Argparse exit 2 before transport. |
| PS-006 | Authorization communication | Top-level/scan help and live preflight | Authorized-use responsibility is visible without claiming authorization was verified. |
| PS-007 | URL validation | Non-http(s), credential-bearing, and unsupported IPv6-literal targets | Exit 2; no transport call. |
| PS-008 | URL normalization | Plain hostname and http(s) URL | Accepted and normalized. |
| PS-009 | Default request profile | Fake live scan without `--user-agent` | All requests use `WAFstat-Scanner/0.4`. |
| PS-010 | User-Agent override | Fake live scan with `--user-agent` | Override applied uniformly to all baseline and marker requests. |
| PS-011 | User-Agent validation | Empty or CR/LF-containing User-Agent | Exit 2; no transport call. |
| PS-012 | Ordinary redirect | HTTP-to-HTTPS redirect preserving query | Final 200 pass-through; not false block. |
| PS-013 | Marker-losing redirect | Redirect drops marker query | `INCONCLUSIVE / MIXED`; warning includes marker preservation loss. |
| PS-014 | Redirect loop | Fake redirect to same sanitized URL | `INCONCLUSIVE / RUNTIME_FAILURE`; error kind `REDIRECT_LOOP`. |
| PS-015 | Redirect depth | More than 5 redirects | `INCONCLUSIVE / RUNTIME_FAILURE`; error kind `REDIRECT_DEPTH_EXHAUSTED`. |
| PS-016 | Cross-host default | Redirect from `example.com` to another host | Destination is not contacted; `INCONCLUSIVE / RUNTIME_FAILURE`; `REDIRECT_OUT_OF_SCOPE`; sanitized blocked hop. |
| PS-016A | Sibling hostname | Redirect from `example.com` to `www.example.com` | Treated as cross-host and stopped by default. |
| PS-016B | Cross-host opt-in | Same redirect with `--follow-cross-host-redirects` | Destination is contacted through fake transport; policy and sanitized warning are recorded. |
| PS-016C | Invalid redirect | Redirect uses a non-HTTP scheme, credentials, or invalid port | Destination is not contacted; `INCONCLUSIVE / RUNTIME_FAILURE`; `REDIRECT_INVALID`. |
| PS-016D | Reflected marker path | Redirect/final `Location` reflects a raw, percent-encoded, plus-encoded, or repeatedly encoded marker in the path | Public URL/header metadata replaces the path with `/[redacted-marker-path]`; output leak guard rejects any retained encoded representation. |
| PS-017 | Transport failure | Fake transport raises `TransportFailure` | `INCONCLUSIVE / RUNTIME_FAILURE`; not enforcement. |
| PS-018 | Challenge signal | Marker responses include `cf-mitigated: challenge` | `ENFORCED / CHALLENGE`. |
| PS-019 | Block signal | Marker responses are 403 with origin-like baseline | `ENFORCED / BLOCK`. |
| PS-019A | Non-block-like HTTP errors | Marker responses are other 4xx/5xx statuses | Marker actions are `OTHER`; aggregate remains `INCONCLUSIVE / MIXED`, not block. |
| PS-020 | Threshold boundary high | 8/9 markers show strong enforcement | `ENFORCED`; strong signal count 8. |
| PS-021 | Threshold boundary low | 7/9 markers show strong enforcement | `INCONCLUSIVE / MIXED`; strong signal count 7. |
| PS-022 | Baseline failure | Same-shape benign baseline is not origin-like | `INCONCLUSIVE`; warning includes `baseline_not_origin_like`. |
| PS-023 | Pass-through | Baseline and all markers return origin-like 2xx | `NOT_ENFORCED_OBSERVED / PASS_THROUGH`; wording remains conditional. |
| PS-024 | Mixed evidence | Some markers block and others pass | `INCONCLUSIVE / MIXED`. |
| PS-025 | Dynamic body drift | All statuses 2xx but body hashes/lengths vary | `NOT_ENFORCED_OBSERVED / PASS_THROUGH`; body hash alone is not block. |
| PS-026 | Saved live output hygiene | Live fake scan saved with `--save-observations` | JSON has no response bodies, no raw marker values, no marker-bearing full URLs. |
| PS-027 | Saved dry-run hygiene | Dry-run saved with `--save-observations` | JSON has no raw marker values and reports dry-run mode. |
| PS-028 | Marker guard raw | Direct call with raw marker value | Raises marker-safety error. |
| PS-029 | Marker guard JSON-escaped | Direct call with JSON-escaped marker value | Raises marker-safety error. |
| PS-030 | Heterogeneous enforcement | Eight challenge observations and one block | `ENFORCED / MIXED`; exact action counts; heterogeneous warning. |
| PS-031 | Partial enforcement diagnostics | Seven blocks and two pass-through observations | `INCONCLUSIVE / MIXED`; pass-through marker IDs listed without values. |
| PS-032 | Threshold retained | Eight blocks and one pass-through | `ENFORCED / BLOCK`; partial-enforcement warning. |
| PS-033 | External-only evidence basis | Pass-through fake scan | Output states no private configuration, provider API, or origin logs were used. |
| PS-034 | Challenge underclaim | Cloudflare-served 403 without `cf-mitigated` | Classified as block, not inferred challenge; warning emitted. |
| PS-035 | Version/schema alignment | Dry-run and live JSON | Tool/request profile version 0.4; authorization notice, redirect policy, evidence basis, block-signal policy, and 8-of-9 threshold present; obsolete acknowledgment field absent. |
| PS-036 | Response identifier hygiene | Fake headers include CDN/origin request IDs or authentication/rate-limit metadata | Persisted response-header subsets omit `cf-ray`, `cf-request-id`, `x-request-id`, `cf-chl-out`, and `x-powered-by`; `www-authenticate` and `retry-after` are reduced to `[present]`. |
| PS-037 | Strict schema closure | Unknown top-level field or baseline marker fields | Published schema rejects unknown top-level fields and marker metadata on baseline observations. |

## Acceptance criteria

Stage 1 is acceptable when all of the following pass:

```bash
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
python3 -m compileall wafstat tests/test_public_wafstat_scanner.py
```

Standalone repository regression is acceptable when all of the following pass:

```bash
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
.venv/bin/python -m py_compile wafstat tests/test_public_wafstat_scanner.py scripts/validate_examples.py
.venv/bin/python scripts/validate_examples.py
git diff --check
```

## Manual dry-run checks

These commands are allowed because they send no network traffic:

```bash
./wafstat scan example.com --dry-run
./wafstat scan example.com --dry-run --json
./wafstat scan example.com --dry-run --json --save-observations /tmp/wafstat_plan.json
```

Expected properties:

- output says `network_activity: none`;
- planned request count is 12;
- request profile is visible;
- evidence basis states that private configuration, provider APIs, and origin logs are not used;
- fixed eight-of-nine enforcement threshold is visible;
- only HTTP 403 without a challenge indicator, authentication header, retry header, or login redirect is treated as a block-like signal;
- marker IDs and categories may be visible;
- raw marker values are absent;
- saved plan parses as JSON.

## Live validation gate

Do not run live validation as part of this test plan. A future live validation plan must specify:

- exact owned/authorized hostname(s);
- expected request count;
- request profile;
- allowed time window;
- whether redirects are expected;
- output path;
- stop conditions;
- post-run leakage checks;
- how results will be interpreted without claiming private WAF state.
