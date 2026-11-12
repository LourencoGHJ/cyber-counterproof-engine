import json
import base64
import subprocess
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from pathlib import Path
from types import SimpleNamespace

import pytest

from cce.live_dashboard import (
    DASHBOARD_HTML,
    DashboardState,
    _DashboardHTTPServer,
    _make_handler,
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
    source_barrier = threading.Barrier(3)

    def fake_run(command, **kwargs):
        calls.append(command)
        source_barrier.wait(timeout=2)
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
    assert "não existe garantia de latência ao nível do milissegundo" in DASHBOARD_HTML




def test_http_dashboard_requires_basic_auth_and_streams_live_events():
    state = DashboardState()
    state.publish({"status": "DRIFT", "summary": {"findings": 1}})
    stop_event = threading.Event()
    username = "cce"
    password = "p" * 24
    handler = _make_handler(state, stop_event, username, password)
    server = _DashboardHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(HTTPError) as unauthorised:
            urlopen(f"{base_url}/api/v1/status", timeout=2)
        assert unauthorised.value.code == 401

        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": "Basic " + token}

        status_request = Request(
            f"{base_url}/api/v1/status",
            headers=headers,
        )
        with urlopen(status_request, timeout=2) as response:
            status = json.loads(response.read().decode("utf-8"))
        assert status["data"]["status"] == "DRIFT"

        event_request = Request(
            f"{base_url}/api/v1/events",
            headers=headers,
        )
        with urlopen(event_request, timeout=2) as response:
            assert response.headers.get_content_type() == "text/event-stream"
            event_lines = [response.readline() for _ in range(4)]
        assert event_lines[0].startswith(b"id: 1")
        assert event_lines[1].startswith(b"event: snapshot")
        assert b'"status":"DRIFT"' in event_lines[2]
        assert event_lines[3] == b"\n"
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
