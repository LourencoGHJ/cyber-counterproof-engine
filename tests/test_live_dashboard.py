import base64
import json
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cce.live_dashboard import (
    LIVE_HTML,
    LiveSnapshotCollector,
    LiveState,
    create_dashboard_server,
    validate_remote_access,
)


def valid_policy():
    return {
        "policy_id": "live-dashboard-test",
        "input_policy": "drop",
        "output_policy": "accept",
        "forward_policy": "drop",
        "rules": [
            {
                "id": "allow-https",
                "chain": "input",
                "action": "accept",
                "protocol": "tcp",
                "source": "any",
                "destination_port": 443,
            }
        ],
    }


def iptables_snapshot():
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )


class FakeCollector:
    requested_source = "test"

    def collect(self):
        return {
            "updated_at_utc": "2026-11-12T10:00:00+00:00",
            "status": "DRIFT",
            "source": "test",
            "scope": "test_scope",
            "partial": False,
            "warnings": [],
            "summary": {"rules_total": 3, "chains_total": 2},
            "findings": [
                {
                    "code": "RULE-MISSING",
                    "rule_id": "allow-https",
                    "reason": "Test finding",
                }
            ],
            "limitations": [],
            "evidence": {},
            "collection_duration_ms": 2.5,
        }


def test_live_collector_auto_prefers_iptables_save_when_available(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")

    tools = {
        "iptables-save": "/usr/sbin/iptables-save",
        "ip6tables-save": None,
        "nft": "/usr/sbin/nft",
    }
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: tools.get(name),
    )

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(
            command, 0, stdout=iptables_snapshot(), stderr=""
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", fake_run)

    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert calls == [["/usr/sbin/iptables-save"]]
    assert result["source"] == "iptables-save"
    assert result["status"] == "INCONCLUSIVE"
    assert result["partial"] is True
    assert result["summary"]["rules_total"] == 1
    assert "ip6tables-save não está instalado" in " ".join(result["warnings"])
    assert "text" not in result
    assert "-A INPUT" not in json.dumps(result)


def test_live_collector_uses_nftables_json_when_iptables_is_unavailable(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: "/usr/sbin/nft" if name == "nft" else None,
    )

    nft_json = {
        "nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "OUTPUT", "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [{"accept": None}]}},
        ]
    }

    def fake_run(command, **kwargs):
        assert command == ["/usr/sbin/nft", "-j", "list", "ruleset"]
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(nft_json), stderr=""
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", fake_run)

    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert result["source"] == "nftables"
    assert result["scope"] == "base_chain_policies_only"
    assert result["summary"]["base_chains"] == 3
    assert result["partial"] is True
    assert result["evidence"]["nftables"]["sha256"]


def test_live_collector_reports_missing_tools_as_error(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr("cce.live_dashboard.shutil.which", lambda _name: None)

    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert result["status"] == "ERROR"
    assert "iptables-save nem nft" in result["error"]


def test_live_collector_reports_permission_errors_without_claiming_safe_state(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: "/usr/sbin/iptables-save" if name == "iptables-save" else None,
    )

    def denied(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="Operation not permitted"
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", denied)

    result = LiveSnapshotCollector(str(policy_path), source="iptables").collect()

    assert result["status"] == "ERROR"
    assert result["findings"] == []
    assert "permissões" in result["error"]


def test_live_collector_rejects_invalid_policy(tmp_path):
    policy_path = tmp_path / "policy.json"
    invalid = valid_policy()
    invalid["input_policy"] = "permit"
    policy_path.write_text(json.dumps(invalid), encoding="utf-8")

    with pytest.raises(ValueError, match="Política inválida"):
        LiveSnapshotCollector(str(policy_path))


def test_live_state_enforces_minimum_poll_interval():
    with pytest.raises(ValueError, match="mínimo"):
        LiveState(FakeCollector(), interval_seconds=0.5)


def test_remote_access_requires_authentication_and_trusted_transport():
    assert validate_remote_access(
        "127.0.0.1",
        allow_remote=False,
        token=None,
        trusted_transport=False,
    ) is False

    with pytest.raises(ValueError, match="--allow-remote"):
        validate_remote_access(
            "0.0.0.0", False, "x" * 40, True
        )

    with pytest.raises(ValueError, match="32 caracteres"):
        validate_remote_access(
            "0.0.0.0", True, "short", True
        )

    with pytest.raises(ValueError, match="VPN ou proxy HTTPS"):
        validate_remote_access(
            "0.0.0.0", True, "x" * 40, False
        )

    assert validate_remote_access(
        "0.0.0.0", True, "x" * 40, True
    ) is True


def test_live_dashboard_html_has_no_branding_and_uses_server_sent_events():
    assert "CYBER COUNTERPROOF" not in LIVE_HTML
    assert "CC E" not in LIVE_HTML
    assert "EventSource" in LIVE_HTML
    assert 'new EventSource("/events")' in LIVE_HTML
    assert "/api/v1/status" in LIVE_HTML
    assert "estado da firewall" in LIVE_HTML.lower()
    assert "textContent" in LIVE_HTML
    assert "innerHTML" not in LIVE_HTML


def test_local_http_server_serves_dashboard_and_live_status():
    state = LiveState(FakeCollector(), interval_seconds=1.0)
    server = create_dashboard_server(
        "127.0.0.1", 0, state, token=None
    )
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    state.start()
    worker.start()
    try:
        address, port = server.server_address[:2]
        base = f"http://{address}:{port}"

        deadline = time.monotonic() + 2
        status = {}
        while time.monotonic() < deadline:
            with urlopen(base + "/api/v1/status", timeout=2) as response:
                status = json.loads(response.read().decode("utf-8"))
            if status.get("sequence", 0) > 0:
                break
            time.sleep(0.02)

        assert status["status"] == "DRIFT"
        assert status["sequence"] >= 1

        with urlopen(base + "/", timeout=2) as response:
            html = response.read().decode("utf-8")
        assert "EventSource" in html
        assert "CYBER COUNTERPROOF" not in html

        with urlopen(base + "/healthz", timeout=2) as response:
            assert json.loads(response.read().decode("utf-8")) == {"ok": True}
    finally:
        state.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_remote_http_server_requires_basic_auth():
    token = "t" * 40
    state = LiveState(FakeCollector(), interval_seconds=1.0)
    server = create_dashboard_server(
        "0.0.0.0",
        0,
        state,
        token=token,
        allow_remote=True,
        trusted_transport=True,
    )
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    state.start()
    worker.start()
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/api/v1/status"
        with pytest.raises(HTTPError) as error:
            urlopen(url, timeout=2)
        assert error.value.code == 401

        request = Request(url)
        credentials = base64.b64encode(f"cce:{token}".encode()).decode("ascii")
        request.add_header("Authorization", "Basic " + credentials)
        with urlopen(request, timeout=2) as response:
            assert response.status == 200
    finally:
        state.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
