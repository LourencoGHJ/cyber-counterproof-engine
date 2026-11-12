import json

import pytest

from cce.cli import main
from cce.snapshot_analysis import analyze_firewall_snapshots


SNAPSHOT_WITH_INDICATORS = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"
    ":OUTPUT ACCEPT [0:0]\n"
    ":FORWARD DROP [0:0]\n"
    "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
    "-A INPUT -p tcp --dport 443 -j DROP\n"
    "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
    "COMMIT\n"
)


def snapshot_entry(text, path="firewall.save"):
    return {"path": path, "sha256": "a" * 64, "text": text}


def test_consolidates_structural_ir_ssh_and_conflict_analysis():
    report = analyze_firewall_snapshots(
        {"ipv4": snapshot_entry(SNAPSHOT_WITH_INDICATORS)}
    )

    assert report["operation"] == "analyze_snapshot"
    assert report["status"] == "INCONCLUSIVE"
    assert report["summary"]["families_analyzed"] == 1
    assert report["summary"]["families_not_provided"] == ["ipv6"]
    assert report["summary"]["rules_total"] == 3
    assert report["summary"]["rules_ir_fully_interpreted"] == 3
    assert report["summary"]["rules_ir_partially_interpreted"] == 0
    assert report["summary"]["ssh_rule_candidates"] == 1
    assert report["summary"]["rule_conflict_findings"] == 1
    assert report["summary"]["proven_rule_conflict_findings"] == 1
    assert report["findings"][0]["category"] == "rule_conflict"
    assert report["findings"][0]["code"] == "SHADOWED_RULE"
    assert any(
        item["category"] == "ssh_rule_candidate"
        for item in report["findings"]
    )


def test_report_does_not_expose_network_or_port_values():
    private_value = "203.0.113.0/24"
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"-A INPUT -s {private_value} -p tcp --dport 2222 -j ACCEPT\n"
        "COMMIT\n"
    )

    report_text = json.dumps(
        analyze_firewall_snapshots({"ipv4": snapshot_entry(text)}),
        ensure_ascii=False,
    )

    assert private_value not in report_text
    assert "2222" not in report_text
    assert "-A INPUT" not in report_text


def test_malformed_snapshot_skips_semantic_analyses():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        "not-an-iptables-rule\n"
        "COMMIT\n"
    )

    report = analyze_firewall_snapshots({"ipv4": snapshot_entry(text)})
    family = report["families"][0]

    assert report["status"] == "INCONCLUSIVE"
    assert report["summary"]["malformed_lines_total"] == 1
    assert family["rule_ir"]["analysis_status"] == "unavailable"
    assert family["risk_indicators"]["analysis_status"] == "skipped"
    assert family["rule_conflicts"]["analysis_status"] == "skipped"
    assert family["chain_flow"]["analysis_status"] == "skipped"
    assert family["risk_indicators"]["candidates"] == []
    assert family["rule_conflicts"]["findings"] == []


def test_rejects_empty_snapshot_mapping():
    with pytest.raises(ValueError, match="pelo menos um snapshot"):
        analyze_firewall_snapshots({})


def test_rejects_unknown_family():
    with pytest.raises(ValueError, match="Famílias não suportadas"):
        analyze_firewall_snapshots(
            {"other": snapshot_entry(SNAPSHOT_WITH_INDICATORS)}
        )


def test_rejects_non_text_family_keys():
    with pytest.raises(ValueError, match="famílias.*texto"):
        analyze_firewall_snapshots(
            {1: snapshot_entry(SNAPSHOT_WITH_INDICATORS)}
        )


def test_cli_writes_consolidated_report_and_returns_inconclusive(
    tmp_path, monkeypatch, capsys
):
    snapshot = tmp_path / "firewall.save"
    output = tmp_path / "reports" / "snapshot-analysis.json"
    snapshot.write_text(
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "COMMIT\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-snapshot",
            "--ipv4", str(snapshot),
            "--output", str(output),
        ],
    )

    assert main() == 3
    assert "CCE: INCONCLUSIVE" in capsys.readouterr().out
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["operation"] == "analyze_snapshot"
    assert report["summary"]["families_analyzed"] == 1
    assert report["families"][0]["chain_flow"]["analysis_status"] == "completed"
