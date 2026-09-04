# WAFstat

WAFstat is a small, standard-library-only command-line tool for authorized
external verification of observable WAF enforcement. It sends a fixed marker
corpus and reports block-like, challenge-like, pass-through, mixed, or runtime
failure observations.

WAFstat does not detect WAF presence, reveal private WAF configuration, mutate
payloads, discover bypasses, crawl targets, or use provider credentials. A
pass-through result means only that no external enforcement signal was observed
for this corpus at the tested path and time.

## Safety and scope

Live mode sends 12 serial HTTP GET probes: three benign baseline requests and
nine fixed marker requests. Each redirect destination is validated before
contact, including an explicit port range of 1-65535. Same-host redirects are
followed with a five-hop cap only while every hop preserves exactly one decoded
probe query value. Otherwise WAFstat stops before the non-preserving destination
and reports `INCONCLUSIVE / RUNTIME_FAILURE`. Cross-host redirects stop before
the destination is contacted unless the operator explicitly enables them; the
maximum is then 72 underlying transport requests when every probe follows five
redirects.

Use WAFstat only on systems you own or are explicitly authorized to assess.
Read `docs/responsible_use.md` before running a live scan.

## Requirements

- Python 3.11 or later
- No third-party runtime packages

## Usage

Inspect a no-network plan:

```bash
./wafstat scan https://authorized.example.test --dry-run
./wafstat scan https://authorized.example.test --dry-run --json
```

Run a live scan only after confirming authorization and scope:

```bash
./wafstat scan https://authorized.example.test
```

Save bodyless, marker-safe JSON metadata:

```bash
./wafstat scan https://authorized.example.test \
  --json \
  --save-observations /tmp/wafstat_observations.json
```

Cross-host redirect following is disabled by default. Enable it only when
every redirect destination is authorized:

```bash
./wafstat scan https://authorized.example.test --follow-cross-host-redirects
```

Only the User-Agent may be customized. A custom value must be non-empty, fit
the standard-library HTTP transport, contain no control characters or fixed
marker representation, and be at most 512 bytes:

```bash
./wafstat scan https://authorized.example.test --user-agent 'Authorized-Audit/1.0'
```

## Output and interpretation

The scanner reports one of these externally observed consequence states:

- `ENFORCED / BLOCK`
- `ENFORCED / CHALLENGE`
- `ENFORCED / MIXED`
- `NOT_ENFORCED_OBSERVED / PASS_THROUGH`
- `INCONCLUSIVE / MIXED`
- `INCONCLUSIVE / RUNTIME_FAILURE`

Only HTTP 403 without the configured challenge indicator or an authentication,
retry, or login header is treated as a block-like enforcement signal. Other
4xx/5xx responses may represent authentication, application, rate-limit, or
upstream failures and remain `OTHER` unless clearer evidence is present.

Saved output excludes response bodies, raw marker values, raw request/provider
identifiers, authentication values, rate-limit timing values, and marker-bearing
query strings. See `docs/public_scanner_output_schema.json` for the JSON
contract and `examples/wafstat_dry_run_example.json` for a no-network example.
WAFstat's own target, request-profile, and observation-write errors do not echo
raw marker-bearing input.

Results are point-in-time external observations. They do not prove WAF presence,
private WAF state, universal behavior, or repeatability across other paths and
times.

## Contributing

Contributor setup and the local functional test command are documented in
`CONTRIBUTING.md`. Tests use injected transports and do not contact live
targets.

## License and citation

WAFstat is released under the MIT License; see `LICENSE`. Citation metadata is
provided in `CITATION.cff`.
