import base64
import json
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cce.cli import make_parser
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
                "service": "https",
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


def test_live_collector_auto_collects_iptables_and_native_nftables(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cce.live_dashboard.platform.system", lambda: "Linux")
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

    nft_json = {
        "nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "OUTPUT", "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}},
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [{"accept": None}]}},
        ]
    }

    def fake_run(command, **kwargs):
        calls.append(command)
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False
        if command == ["/usr/sbin/iptables-save"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=iptables_snapshot(), stderr=""
            )
        assert command == ["/usr/sbin/nft", "-j", "list", "ruleset"]
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(nft_json), stderr=""
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", fake_run)

    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert calls == [
        ["/usr/sbin/iptables-save"],
        ["/usr/sbin/nft", "-j", "list", "ruleset"],
    ]
    assert result["source"] == "iptables-save + nftables"
    assert result["status"] == "INCONCLUSIVE"
    assert result["partial"] is True
    assert result["summary"]["iptables_rules_total"] == 1
    assert result["summary"]["nftables_base_chains"] == 3
    assert "ip6tables-save não está instalado" in " ".join(result["warnings"])
    assert set(result["source_results"]) == {"iptables", "nftables"}
    assert "-A INPUT" not in json.dumps(result)


def test_sudo_readonly_executes_only_fixed_listing_commands(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    tools = {
        "iptables-save": "/usr/sbin/iptables-save",
        "ip6tables-save": None,
        "nft": None,
        "sudo": "/usr/bin/sudo",
    }
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: tools.get(name),
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert "shell" not in kwargs
        return subprocess.CompletedProcess(
            command, 0, stdout=iptables_snapshot(), stderr=""
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", fake_run)
    result = LiveSnapshotCollector(
        str(policy_path),
        source="iptables",
        sudo_readonly=True,
    ).collect()

    assert calls == [
        ["/usr/bin/sudo", "-n", "--", "/usr/sbin/iptables-save"]
    ]
    assert result["status"] == "INCONCLUSIVE"
    assert result["source"] == "iptables-save"


def test_sudo_readonly_fails_closed_when_sudo_is_unavailable(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: "/usr/sbin/iptables-save" if name == "iptables-save" else None,
    )
    result = LiveSnapshotCollector(
        str(policy_path),
        source="iptables",
        sudo_readonly=True,
    ).collect()
    assert result["status"] == "ERROR"
    assert "sudo não foi encontrado" in result["error"]


def test_live_collector_uses_nftables_json_when_iptables_is_unavailable(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("cce.live_dashboard.platform.system", lambda: "Linux")
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
    assert result["summary"]["nftables_base_chains"] == 3
    assert result["partial"] is True
    assert "A análise da fonte nftables tem cobertura limitada" in " ".join(result["warnings"])
    assert result["evidence"]["nftables"]["sha256"]


def test_live_collector_does_not_expose_firewall_selectors(tmp_path, monkeypatch):
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(valid_policy()), encoding='utf-8')
    monkeypatch.setattr(
        'cce.live_dashboard.shutil.which',
        lambda name: '/usr/bin/iptables-save' if name == 'iptables-save' else None,
    )
    raw_snapshot = (
        '*filter\n'
        ':INPUT DROP [0:0]\n'
        ':OUTPUT ACCEPT [0:0]\n'
        ':FORWARD DROP [0:0]\n'
        '-A INPUT -s 203.0.113.77 -d 198.51.100.44 -p tcp --dport 28443 -j ACCEPT\n'
        'COMMIT\n'
    )

    def fake_run(command, **kwargs):
        assert command == ['/usr/bin/iptables-save']
        return subprocess.CompletedProcess(
            command, 0, stdout=raw_snapshot, stderr=''
        )

    monkeypatch.setattr('cce.live_dashboard.subprocess.run', fake_run)
    result = LiveSnapshotCollector(str(policy_path), source='iptables').collect()
    rendered = json.dumps(result)

    for sensitive_value in (
        '203.0.113.77',
        '198.51.100.44',
        '28443',
        '--dport',
        '-A INPUT',
    ):
        assert sensitive_value not in rendered

    assert result['evidence']['iptables']['ipv4']['sha256']


def test_live_collector_reports_missing_tools_as_error(tmp_path, monkeypatch):
    monkeypatch.setattr("cce.live_dashboard.platform.system", lambda: "Linux")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr("cce.live_dashboard.shutil.which", lambda _name: None)

    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert result["status"] == "ERROR"
    assert "iptables-save não está instalado" in result["error"]
    assert "Comando nft não encontrado" in result["error"]


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


def test_live_state_accepts_millisecond_polling_but_rejects_under_100ms():
    state = LiveState(FakeCollector(), interval_seconds=0.1)
    assert state.interval_ms == 100
    with pytest.raises(ValueError, match="100 ms"):
        LiveState(FakeCollector(), interval_seconds=0.05)
    with pytest.raises(ValueError, match="60000 ms"):
        LiveState(FakeCollector(), interval_seconds=60.1)


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


def test_local_http_server_rejects_untrusted_host_header():
    state = LiveState(FakeCollector(), interval_seconds=1.0)
    server = create_dashboard_server('127.0.0.1', 0, state)
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={'poll_interval': 0.02},
        daemon=True,
    )
    worker.start()
    try:
        address, port = server.server_address[:2]
        request = Request(
            f'http://{address}:{port}/healthz',
            headers={'Host': f'attacker.example:{port}'},
        )
        with pytest.raises(HTTPError) as error:
            urlopen(request, timeout=2)
        assert error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


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

        health_url = f"http://127.0.0.1:{port}/healthz"
        with pytest.raises(HTTPError) as health_error:
            urlopen(health_url, timeout=2)
        assert health_error.value.code == 401

        health_request = Request(health_url)
        credentials = base64.b64encode(f"cce:{token}".encode()).decode("ascii")
        health_request.add_header("Authorization", "Basic " + credentials)
        with urlopen(health_request, timeout=2) as response:
            assert response.status == 200
            assert json.loads(response.read().decode("utf-8")) == {"ok": True}

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


def test_cli_exposes_live_dashboard_with_millisecond_interval():
    args = make_parser().parse_args(
        [
            "serve-dashboard",
            "--policy", "config/policy.json",
            "--source", "auto",
            "--interval-ms", "250",
            "--sudo-readonly",
        ]
    )

    assert args.command == "serve-dashboard"
    assert args.interval_ms == 250
    assert args.source == "auto"
    assert args.host == "127.0.0.1"
    assert args.sudo_readonly is True


def test_sse_endpoint_streams_json_updates():
    state = LiveState(FakeCollector(), interval_seconds=1.0)
    server = create_dashboard_server("127.0.0.1", 0, state)
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    state.start()
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while state.snapshot()["sequence"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert state.snapshot()["sequence"] >= 1
        address, port = server.server_address[:2]
        with urlopen(f"http://{address}:{port}/events", timeout=3) as response:
            assert response.headers["Content-Type"].startswith("text/event-stream")
            assert response.headers["Transfer-Encoding"] == "chunked"
            data_line = ""
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line.startswith("data: "):
                    data_line = line[6:]
                    break
            assert data_line
            event = json.loads(data_line)
            assert event["status"] == "DRIFT"
            assert event["sequence"] >= 1
    finally:
        state.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)



class MutableCollector:
    requested_source = "test"

    def __init__(self):
        self.status = "PASS"
        self.calls = 0

    def collect(self):
        self.calls += 1
        return {
            "updated_at_utc": f"check-{self.calls}",
            "status": self.status,
            "source": "test",
            "scope": "test_scope",
            "partial": False,
            "warnings": [],
            "summary": {"rules_total": 2},
            "findings": [],
            "limitations": [],
            "evidence": {"snapshot": {"sha256": "same-hash"}},
            "collection_duration_ms": 2.0 + self.calls,
        }

def test_live_state_survives_unexpected_collector_exception_and_recovers(caplog):
    class RecoveringCollector:
        requested_source = "test"
        def __init__(self):
            self.calls = 0
        def collect(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("private diagnostic detail")
            return FakeCollector().collect()

    collector = RecoveringCollector()
    state = LiveState(collector, interval_seconds=0.1)
    state.start()
    try:
        sequence, failed = state.wait_for_update(0, timeout=1.0)
        assert sequence == 1
        assert failed is not None
        assert failed["status"] == "ERROR"
        assert "RuntimeError" in json.dumps(failed)
        assert "private diagnostic detail" not in json.dumps(failed)
        assert "Falha inesperada na recolha do snapshot CCE" in caplog.text
        assert "RuntimeError" in caplog.text
        assert "private diagnostic detail" not in caplog.text
        assert state.thread.is_alive()

        sequence, recovered = state.wait_for_update(1, timeout=2.0)
        assert sequence == 2
        assert recovered is not None
        assert recovered["status"] == "DRIFT"
        assert state.thread.is_alive()
    finally:
        state.stop()


def test_live_state_deduplicates_unchanged_snapshots_and_publishes_real_changes():
    collector = MutableCollector()
    state = LiveState(collector, interval_seconds=0.1)
    state.start()
    try:
        sequence, first = state.wait_for_update(0, timeout=1.0)
        assert sequence == 1
        assert first is not None
        assert first["status"] == "PASS"
        assert first["data_changed"] is True

        time.sleep(0.25)
        snapshot = state.snapshot()
        assert snapshot["sequence"] == 1
        assert snapshot["data_changed"] is False
        assert snapshot["last_checked_at_utc"] is not None
        assert snapshot["last_changed_at_utc"] == first["last_changed_at_utc"]
        assert snapshot["last_collection_duration_ms"] >= 0

        collector.status = "DRIFT"
        sequence, changed = state.wait_for_update(1, timeout=1.0)
        assert sequence == 2
        assert changed is not None
        assert changed["status"] == "DRIFT"
        assert changed["data_changed"] is True
        assert changed["last_changed_at_utc"] != first["last_changed_at_utc"]
    finally:
        state.stop()


def test_live_state_heartbeat_reports_freshness_without_new_finding_event():
    collector = MutableCollector()
    state = LiveState(collector, interval_seconds=0.1)
    state.start()
    try:
        sequence, _ = state.wait_for_update(0, timeout=1.0)
        assert sequence == 1
        time.sleep(0.15)
        heartbeat = state.heartbeat()
        assert heartbeat["sequence"] == 1
        assert heartbeat["last_checked_at_utc"] is not None
        assert heartbeat["last_collection_duration_ms"] >= 0
        assert heartbeat["interval_ms"] == 100
        assert state.snapshot()["sequence"] == 1
    finally:
        state.stop()


def test_sse_stream_publishes_only_changed_data_and_sends_heartbeats():
    collector = MutableCollector()
    state = LiveState(collector, interval_seconds=0.1)
    server = create_dashboard_server("127.0.0.1", 0, state)
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    state.start()
    worker.start()
    try:
        deadline = time.monotonic() + 2
        while state.snapshot()["sequence"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        address, port = server.server_address[:2]
        with urlopen(f"http://{address}:{port}/events", timeout=3) as response:
            assert response.headers["Content-Type"].startswith("text/event-stream")
            first_event = ""
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line.startswith("data: "):
                    first_event = line[6:]
                    break
            assert first_event
            first = json.loads(first_event)
            assert first["sequence"] == 1
            assert first["status"] == "PASS"

            heartbeat_event = False
            heartbeat_payload = None
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line == "event: heartbeat":
                    heartbeat_event = True
                elif heartbeat_event and line.startswith("data: "):
                    heartbeat_payload = json.loads(line[6:])
                    break
            assert heartbeat_event
            assert heartbeat_payload is not None
            assert heartbeat_payload["sequence"] == 1
            assert heartbeat_payload["last_checked_at_utc"] is not None

            collector.status = "DRIFT"
            second_event = ""
            event_type = "message"
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line.startswith("event: "):
                    event_type = line[7:]
                elif line.startswith("data: "):
                    payload = line[6:]
                    if event_type != "heartbeat":
                        second_event = payload
                        break
                    event_type = "message"
            assert second_event
            second = json.loads(second_event)
            assert second["sequence"] == 2
            assert second["status"] == "DRIFT"
    finally:
        state.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)



def test_live_collector_data_reaches_http_and_sse_and_changes_when_snapshot_changes(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    tools = {
        "iptables-save": "/usr/bin/iptables-save",
        "ip6tables-save": None,
        "nft": None,
    }
    monkeypatch.setattr(
        "cce.live_dashboard.shutil.which",
        lambda name: tools.get(name),
    )

    current_snapshot = {
        "text": iptables_snapshot(),
    }

    def fake_run(command, **kwargs):
        assert command == ["/usr/bin/iptables-save"]
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(
            command, 0, stdout=current_snapshot["text"], stderr=""
        )

    monkeypatch.setattr("cce.live_dashboard.subprocess.run", fake_run)

    collector = LiveSnapshotCollector(str(policy_path), source="iptables")
    state = LiveState(collector, interval_seconds=0.25)
    server = create_dashboard_server("127.0.0.1", 0, state)
    worker = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    state.start()
    worker.start()

    try:
        address, port = server.server_address[:2]
        base = f"http://{address}:{port}"
        first_status = {}
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with urlopen(base + "/api/v1/status", timeout=2) as response:
                first_status = json.loads(response.read().decode("utf-8"))
            if first_status.get("sequence", 0) >= 1:
                break
            time.sleep(0.02)

        assert first_status["sequence"] == 1
        assert first_status["source"] == "iptables-save"
        assert first_status["summary"]["iptables_rules_total"] == 1
        first_hash = first_status["evidence"]["iptables"]["ipv4"]["sha256"]
        assert first_hash
        assert "iptables-save" in first_status["evidence"]["iptables"]["ipv4"]["source"]
        assert "-A INPUT" not in json.dumps(first_status)
        assert "--dport 443" not in json.dumps(first_status)

        with urlopen(base + "/events", timeout=3) as response:
            first_event = ""
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line.startswith("data: "):
                    first_event = line[6:]
                    break
            assert first_event
            first_payload = json.loads(first_event)
            assert first_payload["sequence"] == 1
            assert first_payload["evidence"]["iptables"]["ipv4"]["sha256"] == first_hash

            current_snapshot["text"] = iptables_snapshot().replace(
                "--dport 443", "--dport 22"
            )
            changed_event = ""
            event_type = "message"
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                line = response.readline().decode("utf-8").strip()
                if line.startswith("event: "):
                    event_type = line[7:]
                elif line.startswith("data: "):
                    payload = line[6:]
                    if event_type != "heartbeat":
                        changed_event = payload
                        break
                    event_type = "message"
            assert changed_event
            changed_payload = json.loads(changed_event)
            assert changed_payload["sequence"] == 2
            assert changed_payload["status"] == "DRIFT"
            assert changed_payload["evidence"]["iptables"]["ipv4"]["sha256"] != first_hash
            assert "-A INPUT" not in json.dumps(changed_payload)
            assert "--dport 22" not in json.dumps(changed_payload)
    finally:
        state.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

def test_public_findings_exposes_safe_selector_labels_only():
    from cce.live_dashboard import _public_findings

    result = _public_findings(
        [
            {
                "category": "policy_comparison",
                "unmodelled_selectors": ["input_interface", "tcp_flags"],
                "raw_rule": "example sensitive rule",
                "source_ip": "192.0.2.10",
            }
        ]
    )

    assert result == [
        {
            "category": "policy_comparison",
            "unmodelled_selectors": ["input_interface", "tcp_flags"],
        }
    ]


def test_windows_dashboard_auto_collects_aggregates_without_exposing_rules(
    tmp_path, monkeypatch
):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(valid_policy()), encoding="utf-8")
    monkeypatch.setattr("cce.live_dashboard.platform.system", lambda: "Windows")

    class FakeWindowsAdapter:
        def __init__(self, timeout_seconds):
            assert timeout_seconds == 8.0

        def probe(self):
            return {"available": True, "adapter_id": "windows.defender-firewall"}

        def collect(self):
            return {
                "status": "INCONCLUSIVE",
                "partial": True,
                "warnings": [],
                "summary": {
                    "profiles_total": 3, "profiles_enabled": 3,
                    "rules_total": 549, "rules_enabled": 295,
                    "rules_disabled": 254, "inbound_rules": 311,
                    "outbound_rules": 238, "allow_rules": 548, "block_rules": 1,
                },
                "profiles": [{
                    "name": "Domain", "enabled": "True",
                    "default_inbound_action": "Block",
                    "default_outbound_action": "Allow",
                }],
                "rules": [{
                    "id": "sensitive-rule",
                    "program": ["C:\\Private\\app.exe"],
                    "remote_addresses": ["10.0.0.5"],
                }],
                "evidence": {"windows_active_store": {"sha256": "a" * 64}},
                "limitations": ["Inventory only."],
                "collection_duration_ms": 42.0,
            }

    monkeypatch.setattr(
        "cce.adapters.windows.defender.WindowsDefenderFirewallAdapter",
        FakeWindowsAdapter,
    )
    result = LiveSnapshotCollector(str(policy_path), source="auto").collect()

    assert result["platform"] == "windows"
    assert result["source"] == "Windows Defender Firewall ActiveStore"
    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["windows_rules_total"] == 549
    assert result["summary"]["windows_rules_enabled"] == 295
    assert result["summary"]["windows_rules_disabled"] == 254
    assert result["summary"]["windows_inbound_rules"] == 311
    assert result["summary"]["windows_outbound_rules"] == 238
    assert result["summary"]["windows_allow_rules"] == 548
    assert result["summary"]["windows_block_rules"] == 1
    assert result["profiles"][0]["enabled"] is True
    assert "sensitive-rule" not in json.dumps(result)
    assert "10.0.0.5" not in json.dumps(result)
    assert "C:\\Private" not in json.dumps(result)


def test_live_dashboard_cli_accepts_windows_defender_source():
    args = make_parser().parse_args([
        "serve-dashboard", "--policy", "config/policy.json",
        "--source", "windows-defender",
    ])
    assert args.source == "windows-defender"


def test_live_dashboard_html_contains_windows_inventory_panel():
    assert 'id="windows-details"' in LIVE_HTML
    assert 'id="windows-profiles"' in LIVE_HTML
    assert "Windows Defender Firewall" in LIVE_HTML
