# WAFstat Responsible Use and Authorization Policy

Date: 2026-08-13

## Purpose

WAFstat performs controlled external verification of observable WAF
enforcement on systems the operator owns or is explicitly authorized to test.
It sends fixed marker traffic and reports block-like, challenge-like,
pass-through, mixed, or runtime-failure observations.

WAFstat is not a WAF fingerprinting tool, exploit tool, or bypass-discovery
tool. It does not prove WAF presence or private WAF configuration state.

## Authorization

Run a live scan only when all of the following are true:

1. The target is owned by the operator or covered by explicit administrative
   authorization.
2. The hostname and path are within the approved scope.
3. The operator understands that live mode sends fixed SQLi, XSS, and traversal
   marker strings as HTTP GET query parameters.
4. The operator understands the redirect policy and request bounds below.
5. The operator has considered the operational impact on the target service.

The scanner cannot verify legal or administrative authorization. The operator
remains responsible for the supplied target and any redirect destination that
the operator chooses to follow. WAFstat does not restrict private, loopback,
or link-local address ranges; target selection is entirely the operator's
responsibility.

## Operation and bounds

The deliberate live operation is:

```bash
./wafstat scan https://authorized.example.test
```

Use `--dry-run` to inspect a plan without network activity:

```bash
./wafstat scan https://authorized.example.test --dry-run --json
```

The default live scan is:

- GET only;
- 12 serial logical probes: three benign baselines and nine fixed markers;
- one request at a time;
- 10-second transport timeout;
- five-hop redirect cap;
- at most 72 underlying transport requests when every probe follows five
  redirects;
- HTTP/HTTPS destination validation with explicit ports restricted to
  1-65535; and
- no request-header customization beyond the optional User-Agent override.

Each redirect destination is validated before contact. A followed redirect
must preserve exactly one decoded `wafstat_marker` query value equal to the
current benign or fixed-marker probe at every hop. A missing, blank,
substituted, or duplicated value stops the scan before the non-preserving
destination is contacted and returns `INCONCLUSIVE / RUNTIME_FAILURE`.

Same-host redirects are followed by default. A redirect to another hostname
stops before that destination is contacted and also returns
`INCONCLUSIVE / RUNTIME_FAILURE`. The operator may use
`--follow-cross-host-redirects` only when every destination is authorized.
Sibling hostnames are treated as different hosts.

The default request profile is:

```text
User-Agent: WAFstat-Scanner/0.4
Accept: */*
Accept-Encoding: identity
Connection: close
```

Only `--user-agent` may be overridden. It must be non-empty, at most 512 bytes,
representable by the standard-library HTTP transport, and free of control
characters and fixed marker representations.

## Prohibited use

Do not use WAFstat to:

- scan third-party systems or unrelated domains;
- enumerate public targets;
- test customer systems without written authorization;
- discover bypasses or optimize payload evasion;
- perform credential attacks;
- send session cookies, bearer tokens, clearance tokens, or spoofed client-IP
  headers;
- impersonate browsers or authenticated users;
- exploit vulnerabilities, exfiltrate data, or perform destructive testing;
- increase request volume, concurrency, or scope beyond the documented defaults
  without explicit approval.

The scanner uses a fixed corpus. It does not mutate payloads, fuzz parameters,
crawl paths, or discover application routes.

## Interpretation

WAFstat reports externally observed consequences, not private WAF state. Its
verdict requires no expected label, provider credentials, provider API, origin
logs, or private configuration evidence.

Acceptable phrasing includes:

- “externally observable enforcement was observed”;
- “classified as `ENFORCED / BLOCK` by WAFstat”;
- “consistent with active enforcement if a WAF is present”;
- “no external enforcement observed for this marker corpus”; and
- “if a WAF is present, consistent with detect-only/observe behavior.”

Avoid claims that a WAF is absent, that detect-only mode is proven, that a WAF
was bypassed, or that internal WAF state was confirmed.

The public scanner treats HTTP 403 without the configured challenge indicator
or an authentication, retry, or login header as block-like. Other 4xx/5xx
responses may be application, authentication, rate-limit, or upstream errors
and remain inconclusive unless clearer evidence is present. At least eight of
nine markers must show block/challenge evidence for `ENFORCED`; this is a
disclosed implementation threshold, not universal statistical proof.

One scan is a point-in-time observation. Caching, edge selection, network
jitter, policy transitions, route scope, origin variability, and adaptive
controls can produce heterogeneous results. `INCONCLUSIVE / MIXED` is a valid
outcome.

## Output hygiene

Saved output is bodyless and marker-safe:

- no response bodies or raw marker values;
- no full marker-bearing URLs;
- no credentials, cookies, authorization headers, or clearance tokens;
- authentication and retry metadata represented only as `[present]`;
- sanitized redirect metadata with marker-bearing paths redacted; and
- marker IDs, categories, and hashes rather than marker values.

WAFstat's own target, request-profile, and observation-write errors use stable
diagnostics and do not echo raw marker-bearing input. This guarantee does not
extend to diagnostics produced by shells or external wrappers.

Before sharing saved output, review target names, organizational metadata, and
operationally sensitive headers.
