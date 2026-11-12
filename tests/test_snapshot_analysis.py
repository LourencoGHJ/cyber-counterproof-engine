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


def valid_policy():
    return {
        "policy_id": "baseline-test",
        "input_policy": "drop",
        "output_policy": "accept",
        "forward_policy": "drop",
        "rules": [
            {
                "id": "allow-https-lab",
                "chain": "input",
                "action": "accept",
                "protocol": "tcp",
                "source": "192.0.2.0/24",
                "destination_port": 443,
                "service": "https",
            }
        ],
    }


def policy_snapshot(input_policy="DROP", rule_line=None):
    text = (
        "*filter\n"
        f":INPUT {input_policy} [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
    )
    if rule_line:
        text += rule_line
    return text + "COMMIT\n"


def test_policy_aware_analysis_reports_supported_matches_without_global_pass():
    text = policy_snapshot(
        rule_line="-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
    )

    report = analyze_firewall_snapshots(
        {"ipv4": snapshot_entry(text)},
        policy=valid_policy(),
    )

    comparison = report["policy_comparison"]
    assert report["status"] == "INCONCLUSIVE"
    assert comparison["status"] == "INCONCLUSIVE"
    assert comparison["summary"]["base_policy_matches"] == 3
    assert comparison["summary"]["base_policy_drifts"] == 0
    assert comparison["summary"]["semantic_rule_matches"] == 1
    assert comparison["summary"]["semantic_rule_drifts"] == 0
    assert comparison["summary"]["policy_drift_findings"] == 0
    assert report["summary"]["policy_base_matches"] == 3
    assert report["summary"]["policy_rule_matches"] == 1


def test_policy_aware_analysis_reports_base_and_rule_drifts():
    text = policy_snapshot(
        input_policy="ACCEPT",
        rule_line="-A INPUT -p tcp --dport 443 -j ACCEPT\n",
    )

    report = analyze_firewall_snapshots(
        {"ipv4": snapshot_entry(text)},
        policy=valid_policy(),
    )

    comparison = report["policy_comparison"]
    assert report["status"] == "DRIFT"
    assert comparison["status"] == "DRIFT"
    assert comparison["summary"]["base_policy_drifts"] == 1
    assert comparison["summary"]["semantic_rule_drifts"] == 1
    assert comparison["summary"]["policy_drift_findings"] == 2
    assert report["summary"]["policy_comparison_findings"] == 2
    assert sum(
        item["category"] == "policy_comparison"
        for item in report["findings"]
    ) == 2


def test_policy_comparison_stays_inconclusive_for_malformed_snapshot():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        "not-an-iptables-rule\n"
        "COMMIT\n"
    )

    report = analyze_firewall_snapshots(
        {"ipv4": snapshot_entry(text)},
        policy=valid_policy(),
    )

    comparison = report["policy_comparison"]
    assert comparison["analysis_status"] == "partial"
    assert comparison["summary"]["base_policy_inconclusive"] == 3
    assert comparison["summary"]["semantic_rule_inconclusive"] == 1
    assert comparison["summary"]["policy_drift_findings"] == 0
    assert report["status"] == "INCONCLUSIVE"


def test_policy_aware_analysis_rejects_invalid_policy():
    invalid = valid_policy()
    invalid["input_policy"] = "permit"

    with pytest.raises(ValueError, match="Política inválida"):
        analyze_firewall_snapshots(
            {"ipv4": snapshot_entry(policy_snapshot())},
            policy=invalid,
        )


def test_cli_accepts_optional_policy_and_records_its_hash(
    tmp_path, monkeypatch, capsys
):
    import hashlib

    policy_path = tmp_path / "policy.json"
    snapshot_path = tmp_path / "firewall.save"
    output_path = tmp_path / "full-audit.json"
    policy_data = valid_policy()
    policy_path.write_text(json.dumps(policy_data), encoding="utf-8")
    snapshot_path.write_text(
        policy_snapshot(
            rule_line="-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-snapshot",
            "--policy", str(policy_path),
            "--ipv4", str(snapshot_path),
            "--output", str(output_path),
        ],
    )

    assert main() == 3
    output = capsys.readouterr().out
    assert "CCE: INCONCLUSIVE" in output
    assert "Base coincidentes: 3" in output
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["policy_comparison"]["summary"]["semantic_rule_matches"] == 1
    assert report["policy_evidence"]["sha256"] == hashlib.sha256(
        policy_path.read_bytes()
    ).hexdigest()


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
    output_text = capsys.readouterr().out
    assert "CCE: INCONCLUSIVE" in output_text
    assert "Ciclos potenciais: 0" in output_text
    assert "Chains sem caminho: 0" in output_text
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["operation"] == "analyze_snapshot"
    assert report["summary"]["families_analyzed"] == 1
    assert report["families"][0]["chain_flow"]["analysis_status"] == "completed"
