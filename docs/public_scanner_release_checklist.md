# WAFstat Public Scanner Release Checklist

Date: 2026-08-13
Artifact: `./wafstat`

This checklist is for preparing the public scanner artifact. It is intentionally separate from the research pipeline and paper evidence artifacts.

Offline verification note: items marked `[x]` were verified with injected transports, local static inspection, or the final offline security gate. Live-target validation, repository identity, contact assignment, remote CI execution, and publication approval remain owner-gated and intentionally open.

## 1. Scope and safety gates

- [x] Confirm bare `scan HOST` is the deliberate live operation and is tested only with injected transport during offline validation.
- [x] Confirm `--dry-run` sends no traffic and clearly reports `network_activity: none`.
- [x] Confirm the removed `--execute` and `--i-have-authorization` flags are rejected before transport.
- [x] Confirm CLI help, stderr preflight output, and README display the authorized-use responsibility notice.
- [x] Confirm cross-host redirects stop before destination contact by default with `REDIRECT_OUT_OF_SCOPE`.
- [x] Confirm `--follow-cross-host-redirects` records the opt-in policy and sanitized transition warnings.
- [x] Confirm the checked-in `requirements-dev.txt`, `requirements-security.txt`, and `requirements-semgrep.txt` locks contain hashes and install with `--require-hashes`.
- [x] Confirm no generic `--header` option was added.
- [x] Confirm `--user-agent` rejects empty values and CR/LF injection.
- [x] Confirm no cookies, authorization headers, clearance tokens, referer/origin headers, or spoofed client-IP headers are accepted.
- [x] Confirm the plan remains bounded: 3 baseline + 9 marker logical probes, with at most 72 transport requests when every probe traverses all five redirects.
- [x] Confirm concurrency remains 1.
- [x] Confirm timeout and redirect depth remain bounded.

## 2. Output hygiene

- [x] Confirm response bodies are not saved.
- [x] Confirm raw marker values are not printed or saved.
- [x] Confirm full marker-bearing URLs are not saved.
- [x] Confirm raw, percent-encoded, plus-encoded, and repeatedly encoded marker-bearing URL paths and `Location` values are redacted.
- [x] Confirm saved output contains request headers intended, corpus SHA-256, marker IDs/categories/hashes, sanitized redirects, warnings, and verdict metadata.
- [x] Confirm saved output contains bodyless per-marker actions, evidence-basis provenance, and the fixed eight-of-nine threshold.
- [x] Confirm `ENFORCED / MIXED` is used when block and challenge are both externally observed above threshold.
- [x] Confirm marker-safety checks catch raw, JSON-escaped, percent-encoded, plus-encoded, and repeatedly URL-encoded marker values.

Suggested local leakage check:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import importlib.util, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader('wafstat_tool', './wafstat')
spec = importlib.util.spec_from_loader('wafstat_tool', loader)
mod = importlib.util.module_from_spec(spec)
sys.modules['wafstat_tool'] = mod
loader.exec_module(mod)
paths = [
    Path('README.md'),
    Path('docs/responsible_use.md'),
    Path('docs/public_scanner_test_plan.md'),
    Path('docs/public_scanner_output_schema.json'),
    Path('examples/wafstat_dry_run_example.json'),
]
for path in paths:
    if path.exists():
        text = path.read_text(encoding='utf-8')
        mod.assert_marker_safe(text)
print('marker representation leakage check passed')
PY
```

## 3. Offline validation

Run public scanner tests:

```bash
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
```

Run the standalone scanner tests:

```bash
.venv/bin/python -m pytest tests/test_public_wafstat_scanner.py -q
```

Compile the scanner, tests, and schema validator:

```bash
.venv/bin/python -m py_compile wafstat tests/test_public_wafstat_scanner.py scripts/validate_examples.py
```

Validate the generated example against the published schema:

```bash
.venv/bin/python scripts/validate_examples.py
```

Check patch whitespace:

```bash
git diff --check
```

## 4. Documentation review

- [x] README explains that WAFstat verifies externally observable enforcement rather than WAF presence.
- [x] README includes dry-run and live examples.
- [x] Responsible-use policy states authorized-use requirements and prohibited use.
- [x] Test plan enumerates safety, redirect, classification, and output-hygiene tests.
- [x] Output schema documents bodyless, marker-safe JSON shape.
- [x] Public-scanner output and documentation require no private provider knowledge, expected labels, APIs, or origin logs.
- [x] Citation metadata is present.
- `date-released` is added to `CITATION.cff` only when the v0.4 release date is actually established.
- [x] License is present.

## 5. Live validation gate

Do not run live validation during release preparation unless the operator separately approves a live validation plan.

A live validation plan must specify:

- exact authorized target(s);
- request count;
- request profile;
- output path;
- expected redirect behavior;
- stop conditions;
- post-run leakage checks;
- conservative interpretation language.

## 6. Release notes template

Suggested release-note language:

> WAFstat 0.4 provides a single-file external enforcement-verification scanner for authorized WAF assessment. The `scan` subcommand is the deliberate live operation, while `--dry-run` provides a no-network plan. Same-host redirects are followed by default; cross-host redirects stop before destination contact unless the operator explicitly enables them. WAFstat reports externally observable block/challenge/pass-through/mixed consequences for a fixed marker corpus, includes marker-safe diagnostics and explicit evidence provenance, and requires no expected label or provider-side access. It does not fingerprint WAF presence, claim private WAF state, mutate payloads, or perform bypass discovery.
