# WAFstat

WAFstat is a lightweight external enforcement-verification tool for authorized WAF assessment. For a target the operator owns or is explicitly authorized to test, it checks whether a fixed marker corpus produces externally observable block/challenge behavior, origin-like pass-through, or inconclusive evidence.

WAFstat does not detect WAF presence, infer private WAF configuration state, mutate payloads, discover bypasses, crawl targets, or use provider credentials. A pass-through result means only that no external enforcement signal was observed for this marker corpus at the tested path and time.

## Safety

Live mode sends 12 serial HTTP GET probes: three benign baseline requests and nine fixed marker requests. Same-host redirects are followed with a five-hop cap; cross-host redirects stop before destination contact unless explicitly enabled. Redirects can raise the maximum to 72 underlying transport requests.

Use WAFstat only on systems you own or are explicitly authorized to assess. Review `docs/responsible_use.md` before use.

## Requirements

Runtime:

- Python 3.11 or later
- No third-party runtime packages

Development and tests:

- `pytest`
- `jsonschema`

Optional security tools are maintained in separate hashed locks: `requirements-security.in`/`requirements-security.txt` for Ruff, Bandit, and pip-audit, and `requirements-semgrep.in`/`requirements-semgrep.txt` for the isolated Semgrep environment.

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

Cross-host redirect following is disabled by default. Enable it only when every redirect destination is authorized:

```bash
./wafstat scan https://authorized.example.test --follow-cross-host-redirects
```

## Output

The scanner reports one of these externally observed consequence states:

- `ENFORCED / BLOCK`
- `ENFORCED / CHALLENGE`
- `ENFORCED / MIXED`
- `NOT_ENFORCED_OBSERVED / PASS_THROUGH`
- `INCONCLUSIVE / MIXED`
- `INCONCLUSIVE / RUNTIME_FAILURE`

Only HTTP 403 without the configured challenge indicator or an authentication, retry, or login header is treated as a block-like enforcement signal. Other 4xx/5xx responses may represent authentication, application, rate-limit, or upstream failures and are reported as `OTHER`, producing an inconclusive aggregate result unless another clear signal is present.

Saved output excludes response bodies, raw marker values, raw request/provider identifiers, authentication values, rate-limit timing values, and marker-bearing query strings. `WWW-Authenticate` and `Retry-After` are retained only as `[present]` signals. See `docs/public_scanner_output_schema.json` for the JSON contract.

## Development

Create a repository-local test environment:

```bash
uv venv .venv
uv pip compile --generate-hashes requirements-dev.in -o requirements-dev.txt
uv pip sync --python .venv/bin/python requirements-dev.txt
```

Create the optional repository-local security environment:

```bash
uv venv .venv-security
uv pip compile --generate-hashes requirements-security.in -o requirements-security.txt
uv pip sync --python .venv-security/bin/python requirements-security.txt

# Optional Semgrep environment (isolated because its dependency tree is large)
uv pip compile --generate-hashes requirements-semgrep.in -o requirements-semgrep.txt
uv venv .venv-semgrep
uv pip sync --python .venv-semgrep/bin/python requirements-semgrep.txt
```

Install the Gitleaks binary under `tools/` (Linux x86_64 example):

```bash
mkdir -p tools
TAG=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
  | .venv/bin/python -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])')
VER="${TAG#v}"
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${VER}_linux_x64.tar.gz" \
  | tar -xz -C tools gitleaks
chmod 0755 tools/gitleaks
```

Run the offline checks:

```bash
make test
make compile
make dry-run
make schema-check
make check
```

Security tooling (optional repo-local security environment; no Hermes runtime changes):

```bash
# Secrets (directory then Git object set after the first commit)
./tools/gitleaks dir . --redact --report-format sarif --report-path /tmp/wafstat-gitleaks-dir.sarif
./tools/gitleaks git . --redact --report-format sarif --report-path /tmp/wafstat-gitleaks-git.sarif

# SAST
.venv-security/bin/ruff check --select F,I,B,S wafstat
.venv-security/bin/ruff check --select F,I,B tests scripts
.venv-security/bin/bandit -r wafstat tests scripts -ll -ii

# SCA
.venv-security/bin/pip-audit -r requirements-security.txt
.venv-security/bin/pip-audit -r requirements-semgrep.txt

# Optional extra static rules
.venv-semgrep/bin/semgrep scan --config p/python --config p/security-audit \
  --exclude .venv --exclude .venv-security --exclude .venv-semgrep \
  --exclude tools --exclude .git .
```

Tests use injected fake transports and do not send HTTP requests.

## Repository contents

- `wafstat` — executable, standard-library-only scanner
- `tests/test_public_wafstat_scanner.py` — offline fake-transport tests
- `docs/public_scanner_output_schema.json` — output schema
- `docs/responsible_use.md` — authorization and use policy
- `docs/public_scanner_test_plan.md` — offline test plan
- `docs/public_scanner_release_checklist.md` — release gates
- `docs/security_gate_20260813.md` — latest local gate record
- `examples/wafstat_dry_run_example.json` — generated no-network example
- `CITATION.cff` and `LICENSE` — citation and license metadata
- `requirements-dev.in` / `requirements-dev.txt` — hashed test/schema environment
- `requirements-security.in` / `requirements-security.txt` — hashed SAST/SCA environment
- `requirements-semgrep.in` / `requirements-semgrep.txt` — isolated hashed Semgrep environment
- `.github/workflows/ci.yml` — test, schema, and lint workflow
- `.github/workflows/codeql.yml` — CodeQL workflow
- `.github/dependabot.yml` — dependency update configuration
- `SECURITY.md` and `CONTRIBUTING.md` — public project security and contribution policy

The standalone repository intentionally excludes research targets, observations, provider automation, run state, private validation evidence, drafts, and the research repository’s Git history.

## Release status

This tree remains a release candidate pending independent review, a clean Git-object audit after the first commit, real author/repository metadata, CI execution, and explicit publication approval. Passing local checks does not prove WAF presence, private configuration state, universal WAF behavior, or live-target repeatability.

## License

MIT; see `LICENSE`.
