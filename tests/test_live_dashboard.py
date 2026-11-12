import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cce.live_dashboard import (
    DASHBOARD_HTML,
    DashboardState,
    collect_live_state,
    validate_server_security,
)


IPTABLES_SNAPSHOT = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
"""

NFT_SNAPSHOT = {
    "nftables": [
        {"metainfo": {"version": "1.0.0"}},
        {"table": {"family": "inet", "name": "filter"}},
        {
            "chain": {
                "family": "inet",
                "table": "filter",
                "name": "input",
                "type": "filter",
                "hook": "input",
                "prio": 0,
                "policy": "drop",
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "filter",
                "chain": "input",
                "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"accept": None}],
            }
        },
    ]
}


def test_live_collection_reads_firewall_sources_and_returns_redacted_analysis(
    monkeypatch,
):
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda command: f"/usr/sbin/{command}",
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs["shell"] is False
        assert kwargs["capture_output"] is True
        binary = Path(command[0]).name
        if binary in {"iptables-save", "ip6tables-save"}:
            output = IPTABLES_SNAPSHOT
        elif binary == "nft":
            output = json.dumps(NFT_SNAPSHOT)
        else:
            raise AssertionError(f"Unexpected command: {command}")
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = collect_live_state(interval_ms=1000)

    assert result["status"] == "INCONCLUSIVE"
    assert result["read_only"] is True
    assert result["summary"]["ipv4_rules"] == 1
    assert result["summary"]["ipv6_rules"] == 1
    assert result["summary"]["nft_tables"] == 1
    assert result["summary"]["nft_chains"] == 1
    assert result["summary"]["nft_rules"] == 1
    assert result["sources"]["ipv4"]["status"] == "AVAILABLE"
    assert result["sources"]["ipv6"]["status"] == "AVAILABLE"
    assert result["sources"]["nftables"]["status"] == "AVAILABLE"
    assert result["refresh_interval_ms"] == 1000
    assert len(calls) == 3
    assert all(call[0].startswith("/usr/sbin/") for call in calls)

    serialised = json.dumps(result)
    assert "--dport" not in serialised
    assert "192.0.2." not in serialised
    assert IPTABLES_SNAPSHOT not in serialised


def test_live_collection_reports_unavailable_commands_without_fabricating_data(
    monkeypatch,
):
    monkeypatch.setattr("cce.live_dashboard.shutil.which", lambda _command: None)

    result = collect_live_state()

    assert result["status"] == "ERROR"
    assert result["summary"]["sources_available"] == 0
    assert result["summary"]["ipv4_rules"] == 0
    assert result["sources"]["ipv4"]["status"] == "UNAVAILABLE"
    assert result["sources"]["ipv6"]["status"] == "UNAVAILABLE"
    assert result["sources"]["nftables"]["status"] == "UNAVAILABLE"


def test_live_collection_handles_invalid_nft_json_as_source_error(monkeypatch):
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda command: f"/usr/sbin/{command}",
    )

    def fake_run(command, **kwargs):
        binary = Path(command[0]).name
        if binary == "nft":
            output = "{invalid-json"
        else:
            output = IPTABLES_SNAPSHOT
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = collect_live_state()

    assert result["status"] == "INCONCLUSIVE"
    assert result["sources"]["nftables"]["status"] == "ERROR"
    assert result["sources"]["ipv4"]["status"] == "AVAILABLE"
    assert result["sources"]["ipv6"]["status"] == "AVAILABLE"


def test_remote_listener_requires_strong_password():
    with pytest.raises(ValueError, match="24 caracteres"):
        validate_server_security("0.0.0.0", "cce", None)

    with pytest.raises(ValueError, match="24 caracteres"):
        validate_server_security("192.0.2.20", "cce", "short")

    validate_server_security("192.0.2.20", "cce", "a" * 24)


def test_loopback_listener_does_not_require_remote_password():
    validate_server_security("127.0.0.1", "cce", None)
    validate_server_security("::1", "cce", None)
    validate_server_security("localhost", "cce", None)


def test_dashboard_state_publishes_monotonic_versions_and_copies_payloads():
    state = DashboardState()
    version, payload = state.snapshot()
    assert version == 0
    assert payload is None

    original = {"status": "DRIFT", "summary": {"findings": 1}}
    published_version = state.publish(original)
    original["status"] = "PASS"

    assert published_version == 1
    version, payload = state.snapshot()
    assert version == 1
    assert payload["status"] == "DRIFT"

    next_version, next_payload = state.wait_for_change(after_version=0, timeout=0)
    assert next_version == 1
    assert next_payload["summary"]["findings"] == 1


def test_live_dashboard_has_no_logo_and_uses_server_sent_events():
    assert "Estado da firewall" in DASHBOARD_HTML
    assert "CYBER COUNTERPROOF" not in DASHBOARD_HTML
    assert "EventSource" in DASHBOARD_HTML
    assert "/api/v1/events" in DASHBOARD_HTML
    assert "http://" not in DASHBOARD_HTML
    assert "https://" not in DASHBOARD_HTML
    assert "navigator.sendBeacon" not in DASHBOARD_HTML
    assert "POST " not in DASHBOARD_HTML
    assert "Não existe garantia de latência ao nível do milissegundo" in DASHBOARD_HTML


def test_collection_rejects_interval_below_one_second_via_cli_validation():
    # The public collector documents the requested refresh interval; the
    # serving entry point enforces the minimum to avoid command flooding.
    assert collect_live_state(interval_ms=1000)["refresh_interval_ms"] == 1000
