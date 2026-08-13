"""Offline tests for the single-file public WAFstat live scanner (./wafstat).

No test performs real network activity: every scan uses an injected/fake
transport. The ./wafstat artifact has no .py extension, so it is loaded via
importlib SourceFileLoader; the dry-run path is also exercised via subprocess.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import urllib.parse
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

WAFSTAT_PATH = Path(__file__).resolve().parent.parent / "wafstat"


def _load_module():
    loader = SourceFileLoader("wafstat_tool", str(WAFSTAT_PATH))
    spec = importlib.util.spec_from_loader("wafstat_tool", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["wafstat_tool"] = module
    loader.exec_module(module)
    return module


wafstat = _load_module()


# --- fake transports ---------------------------------------------------------


def _marker_value(mod, url: str) -> str:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    return query.get(mod.MARKER_PARAMETER_NAME, [""])[0]


def _is_baseline(mod, url: str) -> bool:
    return _marker_value(mod, url) == mod.BENIGN_BASELINE_VALUE


def static_transport(
    mod,
    *,
    baseline_status=200,
    baseline_len=1000,
    baseline_headers=None,
    marker_status=403,
    marker_len=200,
    marker_headers=None,
):
    def transport(url, headers, timeout):
        if _is_baseline(mod, url):
            return mod.RawResponse(
                baseline_status,
                dict(baseline_headers or {"content-type": "text/html", "server": "nginx"}),
                b"b" * baseline_len,
            )
        return mod.RawResponse(marker_status, dict(marker_headers or {}), b"m" * marker_len)

    return transport


def raising_transport(mod, exc):
    def transport(url, headers, timeout):
        raise exc

    return transport


# --- 1. dry-run: zero network, no raw markers --------------------------------


def test_dry_run_sends_no_traffic_and_hides_raw_markers(capsys):
    def forbidden_transport(url, headers, timeout):  # pragma: no cover
        raise AssertionError("dry-run must not send traffic")

    rc = wafstat.main(
        ["scan", "example.com", "--dry-run"], transport=forbidden_transport
    )
    out = capsys.readouterr().out
    assert rc == wafstat.EXIT_OK
    assert "mode: dry-run" in out
    assert "network_activity: none" in out
    assert "planned_request_count: 12" in out
    assert "enforcement_threshold: 8/9" in out
    assert "uses_private_configuration: false" in out
    assert "uses_provider_api: false" in out
    assert "uses_origin_logs: false" in out
    assert wafstat.MARKER_CORPUS_SHA256 in out
    for marker in wafstat.MARKERS:
        assert marker.marker_value not in out


def test_dry_run_via_subprocess():
    result = subprocess.run(
        [sys.executable, str(WAFSTAT_PATH), "scan", "example.com", "--dry-run"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == wafstat.EXIT_OK
    assert "network_activity: none" in result.stdout
    assert "planned_request_count: 12" in result.stdout
    for marker in wafstat.MARKERS:
        assert marker.marker_value not in result.stdout


def test_help_states_authorized_use_and_live_redirect_policy():
    result = subprocess.run(
        [sys.executable, str(WAFSTAT_PATH), "scan", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == wafstat.EXIT_OK
    normalized_help = " ".join(result.stdout.split())
    assert "explicitly authorized" in normalized_help
    assert "--dry-run" in normalized_help
    assert "--follow-cross-host-redirects" in normalized_help
    assert "same-host redirects are followed by default" in normalized_help


# --- 2. bare scan is live; --dry-run is the explicit no-network mode ---------


def test_removed_execute_flag_is_rejected_before_transport():
    with pytest.raises(SystemExit) as exc_info:
        wafstat.main(
            ["scan", "example.com", "--execute"],
            transport=raising_transport(wafstat, AssertionError("must not run")),
        )
    assert exc_info.value.code == 2


def test_removed_authorization_flag_is_rejected_before_transport():
    with pytest.raises(SystemExit) as exc_info:
        wafstat.main(
            ["scan", "example.com", "--i-have-authorization"],
            transport=raising_transport(wafstat, AssertionError("must not run")),
        )
    assert exc_info.value.code == 2


def test_dry_run_is_explicitly_no_network(capsys):
    rc = wafstat.main(
        ["scan", "example.com", "--dry-run"],
        transport=raising_transport(wafstat, AssertionError("must not run")),
    )
    out = capsys.readouterr().out
    assert rc == wafstat.EXIT_OK
    assert "mode: dry-run" in out
    assert "network_activity: none" in out


def test_scan_command_runs_live_with_injected_transport(capsys):
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"ok" * 100)

    rc = wafstat.main(
        ["scan", "example.com", "--json"],
        transport=transport,
    )
    assert rc == wafstat.EXIT_OK
    assert len(calls) == 12  # 3 baseline + 9 markers
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert "explicitly authorized" in captured.err


# --- 3. invalid scheme / credentials rejected --------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pass@example.com",
        "http://admin@example.com",
        "https://[::1]/",
        "::1",
    ],
)
def test_invalid_scheme_or_credentials_rejected(host, capsys):
    rc = wafstat.main(
        ["scan", host],
        transport=raising_transport(wafstat, AssertionError("must not run")),
    )
    assert rc == wafstat.EXIT_SAFETY
    assert "wafstat error" in capsys.readouterr().err


def test_plain_hostname_and_https_url_accepted():
    assert wafstat.normalize_target("cf-block.example.com")[0] == "https"
    assert wafstat.normalize_target("http://example.com/app")[0] == "http"


# --- 4/5. User-Agent default, override, CR/LF rejection ----------------------


def test_default_user_agent_used_uniformly():
    seen = []

    def transport(url, headers, timeout):
        seen.append(headers["User-Agent"])
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"ok")

    wafstat.main(
        ["scan", "example.com"],
        transport=transport,
    )
    assert seen == [wafstat.DEFAULT_USER_AGENT] * 12


def test_user_agent_override_applied_uniformly():
    seen = []

    def transport(url, headers, timeout):
        seen.append(headers["User-Agent"])
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"ok")

    wafstat.main(
        [
            "scan",
            "example.com",
            "--user-agent",
            "ResearchScanner/9 contact=sec@example.com",
        ],
        transport=transport,
    )
    assert set(seen) == {"ResearchScanner/9 contact=sec@example.com"}
    assert len(seen) == 12


@pytest.mark.parametrize("bad", ["", "agent\r\ninjected", "agent\nX", "agent\rY"])
def test_empty_or_crlf_user_agent_rejected(bad, capsys):
    rc = wafstat.main(
        ["scan", "example.com", "--user-agent", bad],
        transport=raising_transport(wafstat, AssertionError("must not run")),
    )
    assert rc == wafstat.EXIT_SAFETY
    assert "wafstat error" in capsys.readouterr().err


# --- 6. HTTP->HTTPS redirect is not a false block ----------------------------


def test_http_to_https_redirect_is_not_false_block():
    def transport(url, headers, timeout):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme == "http":
            location = urllib.parse.urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
            return wafstat.RawResponse(301, {"location": location}, b"")
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"origin" * 50)

    verdict = wafstat.run_scan(
        wafstat.normalize_target("http://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_NOT_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_PASS_THROUGH


def test_redirect_drops_marker_query_is_inconclusive():
    def transport(url, headers, timeout):
        parts = urllib.parse.urlsplit(url)
        if parts.path != "/final":
            # Same-host redirect intentionally drops the marker query string.
            location = urllib.parse.urlunsplit(("https", "example.com", "/final", "", ""))
            return wafstat.RawResponse(302, {"location": location}, b"")
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"origin" * 50)

    verdict = wafstat.run_scan(
        wafstat.normalize_target("https://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert "marker_not_preserved_across_redirect" in verdict.warnings


# --- 7. redirect loop / depth exhaustion are inconclusive --------------------


def test_redirect_loop_is_inconclusive_runtime_failure():
    def transport(url, headers, timeout):
        return wafstat.RawResponse(302, {"location": url}, b"")

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_RUNTIME_FAILURE
    assert verdict.error_kind == "REDIRECT_LOOP"


def test_redirect_depth_exhaustion_is_inconclusive_runtime_failure():
    counter = {"n": 0}

    def transport(url, headers, timeout):
        counter["n"] += 1
        location = f"https://example.com/hop{counter['n']}"
        return wafstat.RawResponse(302, {"location": location}, b"")

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_RUNTIME_FAILURE
    assert verdict.error_kind == "REDIRECT_DEPTH_EXHAUSTED"


# --- 8. cross-host redirects stop by default and require explicit opt-in -----


def test_cross_host_redirect_is_not_followed_by_default():
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "example.com":
            location = urllib.parse.urlunsplit(
                ("https", "other.example.net", parts.path, parts.query, "")
            )
            return wafstat.RawResponse(302, {"location": location}, b"")
        raise AssertionError("cross-host destination must not be contacted by default")

    verdict = wafstat.run_scan(
        wafstat.normalize_target("https://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert len(calls) == 1
    assert urllib.parse.urlsplit(calls[0]).hostname == "example.com"
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_RUNTIME_FAILURE
    assert verdict.error_kind == "REDIRECT_OUT_OF_SCOPE"
    assert "did not contact" in verdict.human_summary
    assert "--follow-cross-host-redirects" in verdict.human_summary
    rendered = wafstat.render_verdict(verdict)
    assert "Reason:   REDIRECT_OUT_OF_SCOPE" in rendered
    payload = verdict.as_json()
    assert payload["blocked_redirect"] == {
        "status": 302,
        "from": "https://example.com/",
        "to": "https://other.example.net/",
    }
    assert payload["redirect_policy"] == "same-host-only"


def test_www_redirect_is_cross_host_by_default():
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "example.com":
            return wafstat.RawResponse(
                301,
                {"location": f"https://www.example.com{parts.path}?{parts.query}"},
                b"",
            )
        raise AssertionError("www destination must require explicit opt-in")

    verdict = wafstat.run_scan(
        wafstat.normalize_target("https://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert len(calls) == 1
    assert verdict.error_kind == "REDIRECT_OUT_OF_SCOPE"


def test_blocked_redirect_metadata_is_sanitized():
    marker = wafstat.MARKERS[0]
    marker_url = (
        "https://example.com/?"
        + urllib.parse.urlencode({wafstat.MARKER_PARAMETER_NAME: marker.marker_value})
    )

    encoded_marker = urllib.parse.quote(marker.marker_value, safe="")
    double_encoded_marker = urllib.parse.quote(encoded_marker, safe="")

    def transport(url, headers, timeout):
        return wafstat.RawResponse(
            302,
            {
                "location": (
                    "https://other.example.net/reflect/"
                    + double_encoded_marker
                    + "?secret=marker#fragment"
                )
            },
            b"",
        )

    with pytest.raises(wafstat.RedirectScopeError) as exc_info:
        wafstat.fetch(
            marker_url,
            wafstat.build_request_profile(),
            10.0,
            transport=transport,
        )
    blocked = exc_info.value.blocked_redirect
    assert "?" not in blocked["from"]
    assert "?" not in blocked["to"]
    assert "#" not in blocked["to"]
    serialized = json.dumps(blocked)
    assert marker.marker_value not in serialized
    assert encoded_marker not in serialized
    assert double_encoded_marker not in serialized
    assert "[redacted-marker-path]" in blocked["to"]


def test_marker_reflected_in_location_header_is_redacted():
    marker = wafstat.MARKERS[0]
    encoded_marker = urllib.parse.quote_plus(marker.marker_value, safe="")

    def transport(url, headers, timeout):
        return wafstat.RawResponse(
            200,
            {"location": f"/reflected/{encoded_marker}?discard=this"},
            b"origin",
        )

    verdict = wafstat.run_scan(
        wafstat.normalize_target("https://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    payload = verdict.as_json()
    serialized = json.dumps(payload)
    assert marker.marker_value not in serialized
    assert encoded_marker not in serialized
    assert any(
        obs["response_headers_subset"].get("location")
        == "/[redacted-marker-path]"
        for obs in payload["observations"]
        if obs["kind"] == "marker"
    )


def test_follow_cross_host_redirects_flag_reaches_destination(capsys):
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "example.com":
            location = urllib.parse.urlunsplit(
                ("https", "other.example.net", parts.path, parts.query, "")
            )
            return wafstat.RawResponse(302, {"location": location}, b"")
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"origin")

    rc = wafstat.main(
        ["scan", "example.com", "--follow-cross-host-redirects", "--json"],
        transport=transport,
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert rc == wafstat.EXIT_OK
    assert any(urllib.parse.urlsplit(url).hostname == "other.example.net" for url in calls)
    assert payload["redirect_policy"] == "follow-cross-host"
    assert payload["follow_cross_host_redirects"] is True
    assert any(w.startswith("cross_host_redirect_followed:") for w in payload["warnings"])
    assert "Cross-host redirect following is enabled" in captured.err
    assert "every redirect destination" in captured.err


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:password@other.example.net/",
        "https://other.example.net:invalid/",
    ],
)
def test_invalid_redirect_target_is_never_contacted(location):
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        if len(calls) > 1:
            raise AssertionError("invalid redirect destination must not be contacted")
        return wafstat.RawResponse(302, {"location": location}, b"")

    verdict = wafstat.run_scan(
        wafstat.normalize_target("https://example.com"),
        wafstat.build_request_profile(),
        transport=transport,
        follow_cross_host_redirects=True,
    )
    assert len(calls) == 1
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_RUNTIME_FAILURE
    assert verdict.error_kind == "REDIRECT_INVALID"


# --- 9. transport error is inconclusive, not enforcement ---------------------


def test_transport_error_is_inconclusive_not_enforcement():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=raising_transport(wafstat, wafstat.TransportFailure("URLError")),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_RUNTIME_FAILURE
    assert verdict.enforcement_posture != wafstat.POSTURE_ENFORCED


# --- 10. Cloudflare cf-mitigated challenge -----------------------------------


def test_cloudflare_challenge_is_enforced_challenge():
    transport = static_transport(
        wafstat,
        marker_status=403,
        marker_headers={"cf-ray": "abc", "cf-mitigated": "challenge"},
    )
    verdict = wafstat.run_scan(
        wafstat.normalize_target("cf-block.example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_CHALLENGE


# --- 11. block 403 ------------------------------------------------------------


def test_block_403_is_enforced_block():
    transport = static_transport(wafstat, marker_status=403, marker_len=180)
    verdict = wafstat.run_scan(
        wafstat.normalize_target("modsec-block.example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_BLOCK
    assert verdict.strong_signal_count == 9


@pytest.mark.parametrize("status", [403])
def test_block_like_error_statuses_are_enforced_block(status):
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(wafstat, marker_status=status, marker_len=180),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_BLOCK


@pytest.mark.parametrize(
    "headers",
    [
        {"www-authenticate": "Bearer"},
        {"retry-after": "60"},
        {"location": "/login"},
    ],
)
def test_403_with_auth_rate_limit_or_login_signal_is_other(headers):
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(
            wafstat,
            marker_status=403,
            marker_headers=headers,
            marker_len=180,
        ),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED
    assert verdict.action_counts["OTHER"] == 9


@pytest.mark.parametrize(
    "status",
    [400, 401, 404, 405, 406, 408, 413, 414, 415, 422, 429, 500, 502, 503, 504],
)
def test_non_block_like_error_statuses_are_other_and_inconclusive(status):
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(wafstat, marker_status=status, marker_len=180),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED
    assert verdict.action_counts["OTHER"] == 9


def threshold_transport(strong_count):
    calls = {"marker": 0}

    def transport(url, headers, timeout):
        if _is_baseline(wafstat, url):
            return wafstat.RawResponse(200, {"content-type": "text/html"}, b"b" * 1000)
        calls["marker"] += 1
        if calls["marker"] <= strong_count:
            return wafstat.RawResponse(403, {}, b"blocked")
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"b" * 1000)

    return transport


def action_sequence_transport(actions):
    calls = {"marker": 0}

    def transport(url, headers, timeout):
        if _is_baseline(wafstat, url):
            return wafstat.RawResponse(
                200,
                {"content-type": "text/html", "server": "cloudflare"},
                b"b" * 1000,
            )
        action = actions[calls["marker"]]
        calls["marker"] += 1
        if action == "CHALLENGE":
            return wafstat.RawResponse(
                403,
                {"server": "cloudflare", "cf-mitigated": "challenge"},
                b"challenge",
            )
        if action == "BLOCK":
            return wafstat.RawResponse(403, {"server": "cloudflare"}, b"blocked")
        return wafstat.RawResponse(
            200,
            {"content-type": "text/html", "server": "cloudflare"},
            b"b" * 1000,
        )

    return transport


def test_eight_of_nine_strong_signals_is_enforced_boundary():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=threshold_transport(8),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.strong_signal_count == 8


def test_seven_of_nine_strong_signals_is_inconclusive_boundary():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=threshold_transport(7),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED
    assert verdict.strong_signal_count == 7


def test_heterogeneous_completed_enforcement_actions_are_enforced_mixed():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=action_sequence_transport(["CHALLENGE"] * 8 + ["BLOCK"]),
    )
    payload = verdict.as_json()
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED
    assert payload["action_counts"] == {"BLOCK": 1, "CHALLENGE": 8}
    assert "dominant action" not in payload["evidence_summary"]
    assert "heterogeneous_enforcement_actions" in payload["warnings"]
    assert wafstat.MARKERS[0].marker_id in payload["human_summary"]
    assert wafstat.MARKERS[8].marker_id in payload["human_summary"]


def test_partial_enforcement_keeps_threshold_and_lists_marker_actions():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=action_sequence_transport(["BLOCK"] * 7 + ["PASS_THROUGH"] * 2),
    )
    payload = verdict.as_json()
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED
    assert "partial_enforcement_evidence" in payload["warnings"]
    assert payload["marker_ids_by_action"]["PASS_THROUGH"] == [
        wafstat.MARKERS[7].marker_id,
        wafstat.MARKERS[8].marker_id,
    ]
    assert payload["marker_actions"][0] == {
        "marker_id": wafstat.MARKERS[0].marker_id,
        "marker_category": wafstat.MARKERS[0].marker_category,
        "observed_action": "BLOCK",
    }
    assert wafstat.MARKERS[7].marker_id in payload["human_summary"]
    assert wafstat.MARKERS[8].marker_id in payload["human_summary"]


def test_enforced_with_one_pass_through_remains_block_with_partial_warning():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=action_sequence_transport(["BLOCK"] * 8 + ["PASS_THROUGH"]),
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_BLOCK
    assert "partial_enforcement_evidence" in verdict.warnings


def test_public_output_declares_external_only_evidence_basis_and_threshold():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=action_sequence_transport(["PASS_THROUGH"] * 9),
    )
    payload = verdict.as_json()
    assert payload["evidence_basis"] == {
        "uses_private_configuration": False,
        "uses_provider_api": False,
        "uses_origin_logs": False,
        "baseline_source": "same_scan_benign_probes_following_bounded_redirect_policy",
        "classification_signals": [
            "status_code",
            "cf_mitigated_header",
            "same_scan_baseline_status",
            "redirect_integrity",
            "transport_completion",
        ],
        "block_signal_policy": "http_403_without_challenge_auth_retry_or_login_header",
        "audit_metadata_not_used_for_verdict": ["body_length", "body_sha256"],
    }
    assert payload["enforcement_threshold"] == {"minimum_strong_markers": 8, "marker_count": 9}
    assert "expected_label" not in payload
    assert payload["tool_version"] == "0.4"
    assert "authorization_acknowledged" not in payload
    assert payload["authorized_use_notice"] == wafstat.AUTHORIZED_USE_NOTICE
    assert payload["redirect_policy"] == "same-host-only"
    assert payload["follow_cross_host_redirects"] is False
    assert payload["blocked_redirect"] is None
    plan = wafstat.build_dry_run_plan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
    )
    assert plan["tool_version"] == "0.4"
    assert plan["request_profile"] == "WAFstat-Scanner/0.4-default"
    assert plan["request_headers_intended"]["User-Agent"] == "WAFstat-Scanner/0.4"
    assert "authorization_acknowledged" not in plan
    assert plan["authorized_use_notice"] == wafstat.AUTHORIZED_USE_NOTICE
    assert plan["enforcement_threshold"] == {"minimum_strong_markers": 8, "marker_count": 9}
    assert plan["planned_request_count"] == 12
    assert plan["maximum_transport_requests"] == 72
    assert plan["evidence_basis"]["uses_private_configuration"] is False


def test_public_output_does_not_persist_request_identifiers():
    transport = static_transport(
        wafstat,
        baseline_headers={
            "server": "cloudflare",
            "cf-ray": "ray-secret",
            "cf-request-id": "cf-request-secret",
            "x-request-id": "request-secret",
            "cf-chl-out": "challenge-secret",
            "x-powered-by": "private-origin-detail",
        },
        marker_status=403,
        marker_headers={
            "server": "cloudflare",
            "cf-ray": "ray-secret",
            "cf-request-id": "cf-request-secret",
            "x-request-id": "request-secret",
            "cf-chl-out": "challenge-secret",
            "x-powered-by": "private-origin-detail",
        },
    )
    payload = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    ).as_json()
    serialized = json.dumps(payload)
    for identifier in (
        "cf-ray",
        "cf-request-id",
        "x-request-id",
        "cf-chl-out",
        "x-powered-by",
        "ray-secret",
        "cf-request-secret",
        "request-secret",
        "challenge-secret",
        "private-origin-detail",
    ):
        assert identifier not in serialized


def test_schema_rejects_unknown_top_level_and_invalid_baseline_marker_fields():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads((repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    plan = json.loads((repo / "examples/wafstat_dry_run_example.json").read_text(encoding="utf-8"))
    plan["unexpected_release_field"] = True
    assert list(validator.iter_errors(plan))

    live = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(wafstat, marker_status=200, marker_len=1000),
    ).as_json()
    live["observations"][0]["marker_id"] = wafstat.MARKERS[0].marker_id
    assert list(validator.iter_errors(live))


def test_schema_requires_observations_and_rejects_body_or_request_ids():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    live = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(wafstat, marker_status=200, marker_len=1000),
    ).as_json()

    missing_observations = dict(live)
    missing_observations.pop("observations")
    assert list(validator.iter_errors(missing_observations))

    body_leak = json.loads(json.dumps(live))
    body_leak["observations"][0]["body"] = "not persisted"
    assert list(validator.iter_errors(body_leak))

    request_id_leak = json.loads(json.dumps(live))
    request_id_leak["observations"][0]["response_headers_subset"] = {
        "cf-ray": "request-id-must-not-be-retained"
    }
    assert list(validator.iter_errors(request_id_leak))


def test_schema_allows_sanitized_authentication_signal_header():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    live = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(
            wafstat,
            marker_status=403,
            marker_headers={"www-authenticate": 'Bearer realm="private"'},
            marker_len=180,
        ),
    ).as_json()
    assert live["observations"][3]["response_headers_subset"] == {
        "www-authenticate": "[present]"
    }
    assert not list(validator.iter_errors(live))


def test_schema_allows_sanitized_retry_signal_header():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    live = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(
            wafstat,
            marker_status=403,
            marker_headers={"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"},
            marker_len=180,
        ),
    ).as_json()
    assert live["observations"][3]["response_headers_subset"] == {
        "retry-after": "[present]"
    }
    assert not list(validator.iter_errors(live))


def test_schema_rejects_inconsistent_posture_and_action():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    live = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=static_transport(wafstat, marker_status=200, marker_len=1000),
    ).as_json()
    live["enforcement_posture"] = "ENFORCED"
    live["observed_enforcement_action"] = "PASS_THROUGH"
    live["verdict"] = "ENFORCED / PASS_THROUGH"
    assert list(validator.iter_errors(live))


def test_urllib_transport_marks_truncated_success_and_error_bodies(monkeypatch):
    body = b"x" * (wafstat.MAX_RESPONSE_BYTES + 1)

    class FakeResponse(io.BytesIO):
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()

    class SuccessOpener:
        def open(self, request, timeout):
            return FakeResponse(body)

    monkeypatch.setattr(
        wafstat.urllib.request,
        "build_opener",
        lambda handler: SuccessOpener(),
    )
    success = wafstat.urllib_transport(
        "https://example.com/", wafstat.build_request_profile(), 1.0
    )
    assert success.body == body[: wafstat.MAX_RESPONSE_BYTES]
    assert success.body_truncated is True

    class ErrorOpener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                "blocked",
                {},
                io.BytesIO(body),
            )

    monkeypatch.setattr(
        wafstat.urllib.request,
        "build_opener",
        lambda handler: ErrorOpener(),
    )
    error = wafstat.urllib_transport(
        "https://example.com/", wafstat.build_request_profile(), 1.0
    )
    assert error.body == body[: wafstat.MAX_RESPONSE_BYTES]
    assert error.body_truncated is True


def test_urllib_transport_exact_cap_body_is_not_truncated(monkeypatch):
    body = b"x" * wafstat.MAX_RESPONSE_BYTES

    class FakeResponse(io.BytesIO):
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.close()

    class Opener:
        def open(self, request, timeout):
            return FakeResponse(body)

    monkeypatch.setattr(wafstat.urllib.request, "build_opener", lambda handler: Opener())
    response = wafstat.urllib_transport(
        "https://example.com/", wafstat.build_request_profile(), 1.0
    )
    assert response.body == body
    assert response.body_truncated is False


def test_transport_error_message_is_not_persisted():
    marker = wafstat.MARKERS[0]
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=raising_transport(
            wafstat, wafstat.TransportFailure(marker.marker_value)
        ),
    )
    serialized = json.dumps(verdict.as_json())
    assert marker.marker_value not in serialized
    assert verdict.error_kind == "TRANSPORT_ERROR:TransportFailure"


def test_cloudflare_403_without_challenge_header_is_block_not_inferred_challenge():
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=action_sequence_transport(["BLOCK"] * 9),
    )
    assert verdict.observed_enforcement_action == wafstat.ACTION_BLOCK
    assert "cloudflare_403_without_challenge_header" in verdict.warnings


# --- 12. pass-through ---------------------------------------------------------


def test_baseline_not_origin_like_is_inconclusive():
    transport = static_transport(
        wafstat,
        baseline_status=403,
        baseline_len=200,
        marker_status=403,
        marker_len=200,
    )
    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert "baseline_not_origin_like" in verdict.warnings


def test_pass_through_is_not_enforced_observed():
    transport = static_transport(wafstat, marker_status=200, marker_len=1000)
    verdict = wafstat.run_scan(
        wafstat.normalize_target("control.example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_NOT_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_PASS_THROUGH
    assert "if a waf is present" in verdict.human_summary.lower()


# --- 13. mixed evidence is inconclusive --------------------------------------


def test_mixed_evidence_is_inconclusive():
    marker_calls = {"n": 0}

    def transport(url, headers, timeout):
        if _is_baseline(wafstat, url):
            return wafstat.RawResponse(200, {"content-type": "text/html"}, b"b" * 1000)
        marker_calls["n"] += 1
        if marker_calls["n"] <= 4:
            return wafstat.RawResponse(403, {}, b"blocked")
        return wafstat.RawResponse(200, {"content-type": "text/html"}, b"b" * 1000)

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_INCONCLUSIVE
    assert verdict.observed_enforcement_action == wafstat.ACTION_MIXED


# --- 14. dynamic body hashes alone are not a block signal --------------------


def test_dynamic_body_hashes_do_not_imply_block():
    call = {"n": 0}

    def transport(url, headers, timeout):
        call["n"] += 1
        # 200 everywhere but a unique body (and length) per request.
        return wafstat.RawResponse(
            200, {"content-type": "text/html"}, f"dynamic-body-{call['n']}".encode() * call["n"]
        )

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_NOT_ENFORCED
    assert verdict.observed_enforcement_action == wafstat.ACTION_PASS_THROUGH
    hashes = {o.body_sha256 for o in verdict.observations if o.kind == "marker"}
    assert len(hashes) > 1  # bodies genuinely differed


# --- 15. saved observations are body-less and marker-safe --------------------


def test_saved_observations_are_marker_and_body_safe(tmp_path, capsys):
    transport = static_transport(wafstat, marker_status=403, marker_len=180)
    out_path = tmp_path / "obs.json"
    rc = wafstat.main(
        [
            "scan",
            "modsec-block.example.com",
            "--save-observations",
            str(out_path),
            "--json",
        ],
        transport=transport,
    )
    assert rc == wafstat.EXIT_OK
    text = out_path.read_text(encoding="utf-8")
    data = json.loads(text)

    for marker in wafstat.MARKERS:
        assert marker.marker_value not in text
    # No raw bodies persisted; only derived summaries.
    for obs in data["observations"]:
        assert "body" not in obs
        assert "body_length" in obs
        assert "body_sha256" in obs
        assert "?" not in obs["final_url"]  # marker-bearing query stripped
        if obs["kind"] == "marker":
            assert obs["marker_id"] is not None
            assert obs["marker_value_hash"] is not None
            assert "marker_value" not in obs
    assert data["verdict"] == "ENFORCED / BLOCK"
    assert data["corpus_sha256"] == wafstat.MARKER_CORPUS_SHA256


def test_saved_dry_run_plan_is_marker_safe(tmp_path):
    out_path = tmp_path / "dryrun.json"
    rc = wafstat.main(
        ["scan", "example.com", "--dry-run", "--save-observations", str(out_path), "--json"],
        transport=raising_transport(wafstat, AssertionError("must not run")),
    )
    assert rc == wafstat.EXIT_OK
    text = out_path.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["mode"] == "dry-run"
    for marker in wafstat.MARKERS:
        assert marker.marker_value not in text
        assert json.dumps(marker.marker_value)[1:-1] not in text


def test_assert_marker_safe_raises_on_leak():
    with pytest.raises(wafstat.ScanConfigError):
        wafstat.assert_marker_safe(wafstat.MARKERS[0].marker_value)


def test_assert_marker_safe_raises_on_json_escaped_leak():
    escaped = json.dumps({"bad": wafstat.MARKERS[-1].marker_value})
    with pytest.raises(wafstat.ScanConfigError):
        wafstat.assert_marker_safe(escaped)


@pytest.mark.parametrize(
    "encoder",
    [
        lambda value: urllib.parse.quote(value, safe=""),
        lambda value: urllib.parse.quote_plus(value, safe=""),
        lambda value: urllib.parse.quote(
            urllib.parse.quote(value, safe=""), safe=""
        ),
    ],
)
def test_assert_marker_safe_raises_on_url_encoded_leak(encoder):
    encoded = encoder(wafstat.MARKERS[0].marker_value)
    with pytest.raises(wafstat.ScanConfigError):
        wafstat.assert_marker_safe(json.dumps({"redirect": encoded}))


# --- 16. bounded response reads (hardening: memory-DoS) ----------------------


def test_large_response_body_is_truncated_to_cap():
    # Transport contract returns bytes; truncation is enforced downstream of
    # the transport boundary so a hostile/large response cannot exhaust memory.
    oversize = b"X" * (wafstat.MAX_RESPONSE_BYTES + 42)

    def transport(url, headers, timeout):
        return wafstat.RawResponse(200, {"content-type": "text/html"}, oversize)

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert verdict.enforcement_posture == wafstat.POSTURE_NOT_ENFORCED
    # Body length is capped, not the full response size.
    assert all(o.body_length == wafstat.MAX_RESPONSE_BYTES for o in verdict.observations)
    # Truncation must surface as a warning on observations.
    assert any("response_body_truncated" in o.warnings for o in verdict.observations)


def test_small_response_body_is_not_truncated():
    body = b"ok" * 10

    def transport(url, headers, timeout):
        return wafstat.RawResponse(200, {"content-type": "text/html"}, body)

    verdict = wafstat.run_scan(
        wafstat.normalize_target("example.com"),
        wafstat.build_request_profile(),
        transport=transport,
    )
    assert all(o.body_length == len(body) for o in verdict.observations)
    assert all("response_body_truncated" not in o.warnings for o in verdict.observations)


# --- 17. atomic save-observations (hardening: integrity) --------------------


def test_save_observations_is_atomic_and_marker_safe(tmp_path):
    out_path = tmp_path / "obs.json"
    rc = wafstat.main(
        [
            "scan",
            "modsec-block.example.com",
            "--save-observations",
            str(out_path),
            "--json",
        ],
        transport=static_transport(wafstat, marker_status=403, marker_len=180),
    )
    assert rc == wafstat.EXIT_OK
    text = out_path.read_text(encoding="utf-8")
    json.loads(text)  # complete JSON, not a partial write
    for marker in wafstat.MARKERS:
        assert marker.marker_value not in text
    # No stale temp file left beside the target.
    leftover = [p for p in out_path.parent.iterdir() if p.name.startswith(".")]
    assert leftover == []


def test_save_observations_failure_is_clean_cli_error(tmp_path):
    unwritable = tmp_path / "noPerms" / "obs.json"
    # Parent does not exist; the atomic write must fail cleanly with EXIT_SAFETY
    # and without leaving a partial file.
    rc = wafstat.main(
        [
            "scan",
            "example.com",
            "--dry-run",
            "--json",
            "--save-observations",
            str(unwritable),
        ],
        transport=raising_transport(wafstat, AssertionError("must not run")),
    )
    assert rc == wafstat.EXIT_SAFETY
    assert not unwritable.exists()
    # No partial file or temp file dropped beside the intended destination.
    assert not unwritable.parent.exists() or not any(
        unwritable.parent.iterdir()
    )


def test_output_schema_and_dry_run_example_track_v04_contract():
    repo = Path(__file__).resolve().parents[1]
    schema = json.loads((repo / "docs/public_scanner_output_schema.json").read_text(encoding="utf-8"))
    example = json.loads((repo / "examples/wafstat_dry_run_example.json").read_text(encoding="utf-8"))

    common = schema["$defs"]["common"]
    assert schema["$id"].endswith("public-scanner-output-v0.4.json")
    assert common["properties"]["tool_version"]["const"] == "0.4"
    assert "authorization_acknowledged" not in common["properties"]
    assert "authorized_use_notice" in common["required"]
    assert "redirect_policy" in common["required"]
    assert "follow_cross_host_redirects" in common["required"]
    assert "blocked_redirect" in common["required"]
    assert "markerAction" in schema["$defs"]
    assert "evidenceBasis" in schema["$defs"]
    threshold = schema["$defs"]["enforcementThreshold"]["properties"]["minimum_strong_markers"]
    assert threshold["const"] == 8
    assert example["tool_version"] == "0.4"
    assert example["request_profile"] == "WAFstat-Scanner/0.4-default"
    assert example["evidence_basis"]["uses_provider_api"] is False
    assert example["redirect_policy"] == "same-host-only"
    assert example["follow_cross_host_redirects"] is False
    assert example["blocked_redirect"] is None
    assert example["maximum_transport_requests"] == 72
    assert "authorization_acknowledged" not in example
    assert example["enforcement_threshold"] == {"marker_count": 9, "minimum_strong_markers": 8}
    wafstat.assert_marker_safe(json.dumps(example, sort_keys=True))
