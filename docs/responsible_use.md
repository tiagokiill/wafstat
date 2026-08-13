# WAFstat Responsible Use and Authorization Policy

Date: 2026-08-13

## Purpose

WAFstat is intended for controlled external verification of WAF enforcement posture on systems the operator owns or is explicitly authorized to test. It measures externally observable consequences of fixed marker traffic: block, challenge, pass-through, inconclusive, or runtime failure.

WAFstat is not a WAF fingerprinting tool, not an exploit tool, and not a bypass-discovery tool. It does not claim to prove WAF presence or private WAF configuration state.

## Authorized-use requirement

Run live WAFstat scans only when all of the following are true:

1. The target is owned by the operator or covered by explicit administrative authorization.
2. The tested hostname/path is within the approved scope.
3. The operator understands that live mode sends fixed SQLi/XSS/traversal marker strings as HTTP GET query parameters.
4. The operator understands that same-host redirects are followed by default and that cross-host redirects require explicit opt-in.
5. The operator has considered operational impact on the target service.

The `scan` subcommand is the deliberate live operation:

```bash
./wafstat scan https://authorized.example.test
```

Use `--dry-run` to inspect the plan with no network activity. The scanner cannot verify legal or administrative authorization; responsibility for the supplied target remains with the operator.

## Prohibited use

Do not use WAFstat to:

- scan third-party systems or unrelated domains;
- enumerate public targets;
- test customer systems without written authorization;
- discover bypasses or optimize payload evasion;
- perform credential attacks;
- send session cookies, bearer tokens, clearance tokens, or spoofed client-IP headers;
- impersonate browsers or authenticated users;
- exploit vulnerabilities;
- exfiltrate data;
- perform destructive testing;
- increase request volume, concurrency, or scope beyond the documented defaults without explicit approval.

## Measurement boundaries

WAFstat’s public scanner uses a fixed, non-mutating marker corpus. It does not mutate payloads, fuzz parameters, crawl paths, or discover application routes.

Default live scan shape:

- method: GET only;
- logical probe count: 12 serial probes;
- maximum transport requests with five redirects on every probe: 72;
- baseline: 3 same-shape benign requests;
- markers: 9 fixed marker requests;
- concurrency: 1;
- timeout: 10 seconds;
- redirect cap: 5;
- generic request-header customization: not supported.

The default request profile is:

```text
User-Agent: WAFstat-Scanner/0.4
Accept: */*
Accept-Encoding: identity
Connection: close
```

Only `--user-agent` may be overridden in the current public scanner. The value must be non-empty and must not contain CR/LF characters.

## Interpretation boundaries

WAFstat reports externally observed consequences. It does not report private WAF state.

The public scanner requires no expected label, provider declaration, Cloudflare or ModSecurity credentials, provider API, Security Events, origin logs, or private configuration evidence. Its verdict is derived only from same-scan benign baselines and externally returned responses. Provider-side evidence may be used in an owned laboratory to validate a known condition, but it is not an input to the public scanner and must not overwrite its result.

Acceptable phrasing:

- “externally observable enforcement was observed”;
- “classified as `ENFORCED / BLOCK` by WAFstat”;
- “consistent with active enforcement if a WAF is present”;
- “no external enforcement observed for this marker corpus”;
- “if a WAF is present, consistent with detect-only/observe behavior.”

One scan is a point-in-time external observation. CDN edge selection, recent policy transitions, adaptive controls, route or rule scope, and origin variability can produce heterogeneous results. `INCONCLUSIVE / MIXED` is a valid conservative outcome. A challenge action is reported only when an external indicator supports that detail; a 403 without a challenge, authentication, retry, or login indicator remains block-like enforcement.

The scanner uses a fixed implementation threshold: at least eight of nine markers must show block/challenge evidence for `ENFORCED`. This threshold is disclosed in output and is not a claim of universal statistical proof.

Avoid phrasing such as:

- “the WAF is absent”;
- “detect-only mode is proven”;
- “the WAF was bypassed”;
- “rules were extracted”;
- “internal WAF state was confirmed.”

## Output hygiene

Saved output must remain bodyless and marker-safe:

- no response bodies;
- no raw marker values;
- no full marker-bearing URLs;
- no credentials, cookies, authorization headers, or clearance tokens;
- authentication challenge metadata is reduced to the presence marker `[present]`;
- rate-limit retry timing metadata is reduced to the presence marker `[present]`;
- sanitized redirect metadata only; raw, percent-encoded, plus-encoded, and repeatedly encoded marker-bearing paths are replaced with `/[redacted-marker-path]`;
- marker IDs/categories/hashes rather than marker values.
- bodyless per-marker observed-action diagnostics, evidence-basis metadata, and the disclosed enforcement threshold.

Before sharing saved output, review it for target names, organizational metadata, and operationally sensitive headers.

The marker-safety guard applies the same detection to retained `Location` values and rejects output containing raw, JSON-escaped, percent-encoded, plus-encoded, or repeatedly URL-encoded marker representations.

## Cross-host redirects

The scanner follows same-host redirects by default and classifies the final response. A redirect to a different hostname stops before the destination is contacted and returns `INCONCLUSIVE / RUNTIME_FAILURE` with `error_kind: REDIRECT_OUT_OF_SCOPE`.

If every redirect destination is authorized, the operator may rerun with `--follow-cross-host-redirects`. The override follows cross-host transitions within the redirect cap and records sanitized warnings. It does not establish authorization. WAFstat treats sibling names such as `example.test` and `www.example.test` as different hostnames rather than assuming common scope.

## Recommended operating procedure

1. Confirm written authorization and target scope.
2. Run dry-run mode and save the plan.
3. Review planned request count, request profile, target normalization, and redirect expectations.
4. Run `scan` without `--dry-run` only if the plan matches the approved scope.
5. Save bodyless JSON observations and verdict metadata.
6. Interpret results conservatively and preserve warnings/limitations with the result.

Dry-run example:

```bash
./wafstat scan https://authorized.example.test --dry-run --json --save-observations /tmp/wafstat_plan.json
```

Live example after authorization review:

```bash
./wafstat scan https://authorized.example.test \
  --json \
  --save-observations /tmp/wafstat_observations.json
```
