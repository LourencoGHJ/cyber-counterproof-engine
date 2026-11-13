import json

import pytest

from cce.adapters.linux.netfilter import LinuxNetfilterAdapter
from cce.adapters.registry import create_firewall_adapter
from cce.cli import main


def valid_policy():
    return {
        "policy_id": "adapter-test",
        "input_policy": "drop",
        "output_policy": "accept",
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


def test_linux_registry_selects_netfilter_adapter(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(valid_policy()), encoding="utf-8")

    adapter = create_firewall_adapter(
        policy_path=str(policy),
        system="linux",
    )

    assert isinstance(adapter, LinuxNetfilterAdapter)
    assert adapter.adapter_id == "linux.netfilter"


def test_linux_adapter_reports_available_tools(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(valid_policy()), encoding="utf-8")

    tools = {
        "iptables-save": "/usr/bin/iptables-save",
        "ip6tables-save": "/usr/bin/ip6tables-save",
        "nft": "/usr/bin/nft",
    }
    monkeypatch.setattr(
        "cce.adapters.linux.netfilter.shutil.which",
        lambda name: tools.get(name),
    )

    adapter = LinuxNetfilterAdapter(str(policy))
    result = adapter.probe()

    assert result["available"] is True
    assert result["read_only"] is True
    assert result["permission_probe"] == "not_performed"


def test_linux_adapter_detects_missing_tools(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(valid_policy()), encoding="utf-8")

    monkeypatch.setattr(
        "cce.adapters.linux.netfilter.shutil.which",
        lambda _name: None,
    )

    adapter = LinuxNetfilterAdapter(str(policy))
    assert adapter.probe()["available"] is False


def test_factory_selects_windows_defender_adapter(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(valid_policy()), encoding="utf-8")

    from cce.adapters.windows.defender import (
        WindowsDefenderFirewallAdapter,
    )

    adapter = create_firewall_adapter(
        policy_path=str(policy),
        system="windows",
    )

    assert isinstance(adapter, WindowsDefenderFirewallAdapter)


def test_collect_cli_writes_report(tmp_path, monkeypatch, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(valid_policy()), encoding="utf-8")
    output = tmp_path / "reports" / "collection.json"

    class FakeAdapter:
        def probe(self):
            return {
                "adapter_id": "test.adapter",
                "platform": "linux",
                "available": True,
            }

        def collect(self):
            return {
                "status": "INCONCLUSIVE",
                "source": "test",
                "partial": True,
                "summary": {"rules_total": 4},
                "warnings": [],
                "findings": [],
                "evidence": {},
            }

    monkeypatch.setattr(
        "cce.cli.create_firewall_adapter",
        lambda **_kwargs: FakeAdapter(),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "collect",
            "--policy", str(policy),
            "--once",
            "--output", str(output),
        ],
    )

    assert main() == 3
    assert output.is_file()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "INCONCLUSIVE"
    assert report["summary"]["rules_total"] == 4
    assert "test.adapter" in capsys.readouterr().out


def test_collect_parser_requires_once_flag():
    from cce.cli import make_parser

    with pytest.raises(SystemExit):
        make_parser().parse_args(
            ["collect", "--policy", "config/policy.json"]
        )

    args = make_parser().parse_args(
        ["collect", "--policy", "config/policy.json", "--once"]
    )
    assert args.command == "collect"
