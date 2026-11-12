import json

import pytest

from cce.cli import main
from cce.iptables_chain_flow import analyze_iptables_chain_flow


def snapshot(rules="", extra_chains="", extra_tables=""):
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"{extra_chains}"
        f"{rules}"
        "COMMIT\n"
        f"{extra_tables}"
    )


def test_tracks_ordered_jump_and_goto_edges_and_structural_reachability():
    result = analyze_iptables_chain_flow(
        snapshot(
            "-A INPUT -j app\n"
            "-A app -g leaf\n",
            ":app - [0:0]\n"
            ":leaf - [0:0]\n"
            ":orphan - [0:0]\n",
        ),
        "ipv4",
    )

    assert result["analysis_status"] == "completed"
    assert result["summary"]["base_chains_total"] == 3
    assert result["summary"]["structurally_reachable_user_chains"] == 2
    assert result["summary"]["structurally_unreachable_user_chains"] == 1
    assert result["summary"]["jump_references"] == 1
    assert result["summary"]["goto_references"] == 1
    assert [edge["operation"] for edge in result["edges"]] == ["jump", "goto"]
    assert [edge["line_number"] for edge in result["edges"]] == [8, 9]
    assert result["summary"]["cyclic_components_total"] == 0
    assert any(
        item["code"] == "STRUCTURALLY_UNREACHABLE_CHAIN"
        and item["chain"] == "orphan"
        for item in result["findings"]
    )


def test_reports_reachable_multi_chain_cycle_as_potential_recursion():
    result = analyze_iptables_chain_flow(
        snapshot(
            "-A INPUT -j app\n"
            "-A app -j leaf\n"
            "-A leaf -g app\n",
            ":app - [0:0]\n"
            ":leaf - [0:0]\n",
        ),
        "ipv4",
    )

    assert result["summary"]["cyclic_components_total"] == 1
    finding = next(
        item for item in result["findings"]
        if item["code"] == "POTENTIAL_CHAIN_RECURSION"
    )
    assert finding["certainty"] == "potential"
    assert finding["chains"] == ["app", "leaf"]
    assert finding["structurally_reachable_from_base"] is True
    assert finding["line_numbers"] == [9, 10]


def test_reports_self_reference_as_potential_cycle():
    result = analyze_iptables_chain_flow(
        snapshot(
            "-A app -j app\n",
            ":app - [0:0]\n",
        ),
        "ipv4",
    )

    assert result["summary"]["cyclic_components_total"] == 1
    finding = result["findings"][0]
    assert finding["code"] == "POTENTIAL_CHAIN_RECURSION"
    assert finding["certainty"] == "potential"
    assert finding["structurally_reachable_from_base"] is False


def test_unresolved_target_is_not_assumed_to_be_a_missing_chain():
    result = analyze_iptables_chain_flow(
        snapshot("-A INPUT -j unknown-extension-target\n"),
        "ipv4",
    )

    assert result["summary"]["unresolved_targets_total"] == 1
    assert result["unresolved_targets"][0]["target"] == "unknown-extension-target"
    assert not any(
        item["code"] == "STRUCTURALLY_UNREACHABLE_CHAIN"
        for item in result["findings"]
    )


def test_ignores_chain_references_from_other_tables():
    extra_tables = (
        "*nat\n"
        ":PREROUTING ACCEPT [0:0]\n"
        ":POSTROUTING ACCEPT [0:0]\n"
        ":nat-child - [0:0]\n"
        "-A PREROUTING -j nat-child\n"
        "COMMIT\n"
    )
    result = analyze_iptables_chain_flow(
        snapshot(extra_tables=extra_tables),
        "ipv4",
    )

    assert result["table"] == "filter"
    assert result["summary"]["chains_total"] == 3
    assert result["summary"]["chain_references_total"] == 0


def test_marks_graph_partial_when_snapshot_has_malformed_lines():
    result = analyze_iptables_chain_flow(
        snapshot("not-an-iptables-rule\n"),
        "ipv4",
    )

    assert result["analysis_status"] == "partial"
    assert result["summary"]["malformed_lines"] == 1


def test_rejects_unsupported_family():
    with pytest.raises(ValueError, match="ipv4"):
        analyze_iptables_chain_flow(snapshot(), "inet")


def test_cli_writes_chain_flow_report_and_returns_findings(
    tmp_path, monkeypatch, capsys
):
    snapshot_path = tmp_path / "firewall.save"
    output = tmp_path / "reports" / "chain-flow.json"
    snapshot_path.write_text(
        snapshot(
            "-A INPUT -j app\n"
            "-A app -j app\n",
            ":app - [0:0]\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "cce",
            "analyze-chain-flow",
            "--snapshot", str(snapshot_path),
            "--family", "ipv4",
            "--output", str(output),
        ],
    )

    assert main() == 1
    stdout = capsys.readouterr().out
    assert "CCE: CHAIN_FLOW" in stdout
    assert "Ciclos potenciais: 1" in stdout

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["operation"] == "analyze_chain_flow"
    assert report["result"]["summary"]["cyclic_components_total"] == 1
