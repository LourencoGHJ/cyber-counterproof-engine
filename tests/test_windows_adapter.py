import hashlib
import json
from types import SimpleNamespace

import pytest

import cce.adapters.windows.defender as defender
from cce.adapters.windows.defender import WindowsDefenderFirewallAdapter


def make_payload():
    return {
        "schema_version": 1,
        "platform": "windows",
        "policy_store": "ActiveStore",
        "collected_at_utc": "2026-11-12T12:00:00Z",
        "profiles": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": "False"},
        ],
        "rules": [
            {
                "id": "rule-1",
                "enabled": True,
                "direction": "Inbound",
                "action": "Block",
            },
            {
                "id": "rule-2",
                "enabled": "False",
                "direction": "Outbound",
                "action": "Allow",
            },
            {
                "id": "rule-3",
                "enabled": True,
                "direction": None,
                "action": None,
            },
        ],
    }


def configure_windows(monkeypatch, adapter):
    monkeypatch.setattr(
        defender.platform,
        "system",
        lambda: "Windows",
    )
    monkeypatch.setattr(
        adapter,
        "_powershell",
        lambda: "powershell.exe",
    )


def test_probe_detects_available_windows_powershell(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()

    monkeypatch.setattr(
        defender.platform,
        "system",
        lambda: "Windows",
    )
    monkeypatch.setattr(
        defender.shutil,
        "which",
        lambda name: "C:/Windows/System32/powershell.exe"
        if name == "powershell.exe"
        else None,
    )

    result = adapter.probe()

    assert result["available"] is True
    assert result["status"] == "available"
    assert result["read_only"] is True
    assert result["permission_probe"] == "not_performed"


def test_probe_rejects_non_windows_platform(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()

    monkeypatch.setattr(
        defender.platform,
        "system",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        defender.shutil,
        "which",
        lambda _name: "/usr/bin/pwsh",
    )

    result = adapter.probe()

    assert result["available"] is False
    assert result["status"] == "platform_mismatch"


def test_collect_rejects_non_windows_platform(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()

    monkeypatch.setattr(
        defender.platform,
        "system",
        lambda: "Linux",
    )

    with pytest.raises(RuntimeError, match="só pode ser consultado no Windows"):
        adapter.collect()


def test_collect_rejects_missing_powershell(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()

    monkeypatch.setattr(
        defender.platform,
        "system",
        lambda: "Windows",
    )
    monkeypatch.setattr(
        adapter,
        "_powershell",
        lambda: None,
    )

    with pytest.raises(RuntimeError, match="PowerShell não encontrado"):
        adapter.collect()


def test_collect_normalizes_rules_and_generates_evidence(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter(timeout_seconds=5)
    configure_windows(monkeypatch, adapter)

    payload = make_payload()
    raw = json.dumps(payload)

    monkeypatch.setattr(
        defender.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=raw,
            stderr="",
        ),
    )

    result = adapter.collect()

    assert result["platform"] == "windows"
    assert result["adapter_id"] == "windows.defender-firewall"
    assert result["status"] == "INCONCLUSIVE"
    assert result["partial"] is True

    assert result["summary"] == {
        "profiles_total": 2,
        "profiles_enabled": 1,
        "rules_total": 3,
        "rules_enabled": 2,
        "rules_disabled": 1,
        "inbound_rules": 1,
        "outbound_rules": 1,
        "allow_rules": 1,
        "block_rules": 1,
    }

    expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    actual_hash = result["evidence"]["windows_active_store"]["sha256"]

    assert actual_hash == expected_hash
    assert result["collected_at_utc"] == payload["collected_at_utc"]


def test_collect_handles_powershell_timeout(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter(timeout_seconds=3)
    configure_windows(monkeypatch, adapter)

    def timeout(*args, **kwargs):
        raise defender.subprocess.TimeoutExpired(
            cmd="powershell.exe",
            timeout=3,
        )

    monkeypatch.setattr(defender.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="excedeu 3 segundos"):
        adapter.collect()


def test_collect_handles_powershell_os_error(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()
    configure_windows(monkeypatch, adapter)

    def fail(*args, **kwargs):
        raise OSError("process could not start")

    monkeypatch.setattr(defender.subprocess, "run", fail)

    with pytest.raises(RuntimeError, match="Não foi possível iniciar PowerShell"):
        adapter.collect()


def test_collect_handles_nonzero_powershell_exit(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()
    configure_windows(monkeypatch, adapter)

    monkeypatch.setattr(
        defender.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Access denied",
        ),
    )

    with pytest.raises(RuntimeError, match="Access denied"):
        adapter.collect()


def test_collect_rejects_invalid_json(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()
    configure_windows(monkeypatch, adapter)

    monkeypatch.setattr(
        defender.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="not-json",
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="JSON válido"):
        adapter.collect()


def test_collect_rejects_non_object_snapshot(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()
    configure_windows(monkeypatch, adapter)

    monkeypatch.setattr(
        defender.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='["invalid", "snapshot"]',
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="Snapshot Windows inválido"):
        adapter.collect()


def test_adapter_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="superior a zero"):
        WindowsDefenderFirewallAdapter(timeout_seconds=0)


def test_collect_summary_uses_lightweight_script_and_returns_only_aggregates(
    monkeypatch,
):
    adapter = WindowsDefenderFirewallAdapter(timeout_seconds=7)
    configure_windows(monkeypatch, adapter)
    payload = {
        "schema_version": 1,
        "platform": "windows",
        "policy_store": "ActiveStore",
        "collected_at_utc": "2026-11-13T22:30:00Z",
        "summary": {
            "profiles_total": 3,
            "profiles_enabled": 3,
            "rules_total": 549,
            "rules_enabled": 295,
            "rules_disabled": 254,
            "inbound_rules": 311,
            "outbound_rules": 238,
            "allow_rules": 548,
            "block_rules": 1,
        },
        "profiles": [
            {
                "name": "Domain",
                "enabled": "True",
                "default_inbound_action": "Block",
                "default_outbound_action": "Allow",
            }
        ],
        "rule_fingerprint": '[{"Name":"Rule-A","Enabled":true}]',
    }
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        assert command[-1] == defender.DASHBOARD_POWERSHELL_SCRIPT
        assert "Get-NetFirewallPortFilter" not in command[-1]
        assert "Get-NetFirewallAddressFilter" not in command[-1]
        assert kwargs["timeout"] == 7
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(defender.subprocess, "run", fake_run)

    result = adapter.collect_summary()

    assert len(calls) == 1
    assert result["summary"]["rules_total"] == 549
    assert result["summary"]["rules_enabled"] == 295
    assert result["profiles"] == [
        {
            "name": "Domain",
            "enabled": True,
            "default_inbound_action": "Block",
            "default_outbound_action": "Allow",
        }
    ]
    assert "rules" not in result
    assert "rule_fingerprint" not in result
    assert result["evidence"]["windows_active_store"]["sha256"] == hashlib.sha256(
        payload["rule_fingerprint"].encode("utf-8")
    ).hexdigest()


def test_collect_summary_rejects_non_windows_platform(monkeypatch):
    adapter = WindowsDefenderFirewallAdapter()
    monkeypatch.setattr(defender.platform, "system", lambda: "Linux")

    with pytest.raises(RuntimeError, match="só pode ser consultado no Windows"):
        adapter.collect_summary()


def test_dashboard_script_does_not_query_associated_filters_per_rule():
    assert "Get-NetFirewallRule -PolicyStore ActiveStore" in defender.DASHBOARD_POWERSHELL_SCRIPT
    assert "Get-NetFirewallPortFilter" not in defender.DASHBOARD_POWERSHELL_SCRIPT
    assert "Get-NetFirewallAddressFilter" not in defender.DASHBOARD_POWERSHELL_SCRIPT
    assert "Get-NetFirewallApplicationFilter" not in defender.DASHBOARD_POWERSHELL_SCRIPT

