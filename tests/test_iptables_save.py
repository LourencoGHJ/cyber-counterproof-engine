import json

import pytest

from cce.iptables_save import (
    analyze_iptables_saves,
    parse_iptables_save,
)


def sample(input_policy="DROP", include_forward=True):
    forward = (
        ":FORWARD DROP [0:0]\n"
        if include_forward
        else ""
    )

    return (
        "*filter\n"
        f":INPUT {input_policy} [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        f"{forward}"
        ":ufw-before-input - [0:0]\n"
        ":orphan - [0:0]\n"
        "-A INPUT -m conntrack "
        "--ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A INPUT -j ufw-before-input\n"
        "-A ufw-before-input -p tcp -m tcp "
        "--dport 2222 -j ACCEPT\n"
        "COMMIT\n"
    )


def policy():
    return {
        "policy_id": "test-baseline",
        "input_policy": "drop",
        "output_policy": "accept",
        "forward_policy": "drop",
        "rules": [],
    }


def test_parse_counts_chains_rules_and_modules():
    result = parse_iptables_save(sample(), "ipv4")

    assert result["summary"]["tables_total"] == 1
    assert result["summary"]["chains_total"] == 5
    assert result["summary"]["rules_total"] == 3
    assert result["match_modules"]["conntrack"] == 1
    assert result["match_modules"]["tcp"] == 1
    assert result["summary"]["malformed_lines"] == 0


def test_follows_jump_and_identifies_chain_without_explicit_path():
    result = parse_iptables_save(sample(), "ipv4")

    assert result["summary"]["jump_references"] == 1
    assert result["summary"]["goto_references"] == 0
    assert result["summary"]["chains_without_explicit_path"] == 1
    assert result["chains_without_explicit_path"][0]["name"] == "orphan"


def test_unknown_target_is_unresolved_not_assumed_to_be_a_chain():
    text = sample() + (
        "*filter\n"
        "COMMIT\n"
    )
    # Usa um target desconhecido numa regra válida estruturalmente.
    text = text.replace(
        "-A INPUT -j ufw-before-input\n",
        "-A INPUT -j cce-unknown-extension\n"
        "-A INPUT -j ufw-before-input\n",
    )

    result = parse_iptables_save(text, "ipv4")

    assert result["summary"]["unresolved_targets"] == 1
    assert result["unresolved_targets"][0]["target"] == (
        "cce-unknown-extension"
    )


def test_missing_source_chain_is_rejected():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        "-A MISSING -j ACCEPT\n"
        "COMMIT\n"
    )

    with pytest.raises(ValueError, match="chain de origem inexistente"):
        parse_iptables_save(text, "ipv4")


def test_duplicate_chain_is_rejected():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":INPUT DROP [0:0]\n"
        "COMMIT\n"
    )

    with pytest.raises(ValueError, match="Chain duplicada"):
        parse_iptables_save(text, "ipv4")


def test_report_does_not_store_port_values():
    result = parse_iptables_save(sample(), "ipv4")

    rendered = json.dumps(result, ensure_ascii=False)

    assert "2222" not in rendered
    assert "--dport" in rendered


def test_matching_ipv4_ipv6_base_policies_remain_inconclusive():
    result = analyze_iptables_saves(
        policy(),
        sample(),
        sample(),
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["base_policies_matched"] == 6
    assert result["summary"]["base_policy_mismatches"] == 0
    assert result["summary"]["rules_semantically_compared"] == 0


def test_detects_ipv6_input_policy_mismatch():
    result = analyze_iptables_saves(
        policy(),
        sample(),
        sample(input_policy="ACCEPT"),
    )

    assert result["status"] == "DRIFT"
    assert result["summary"]["base_policy_mismatches"] == 1

    finding = result["findings"][0]
    assert finding["family"] == "ipv6"
    assert finding["chain"] == "INPUT"
    assert finding["expected"] == "DROP"
    assert finding["observed"] == "ACCEPT"


def test_detects_missing_forward_chain():
    result = analyze_iptables_saves(
        policy(),
        sample(),
        sample(include_forward=False),
    )

    assert result["status"] == "DRIFT"
    assert any(
        finding["code"] == "CCE-IPTABLES-BASE-CHAIN-MISSING"
        and finding["family"] == "ipv6"
        and finding["chain"] == "FORWARD"
        for finding in result["findings"]
    )


def test_rejects_empty_snapshot():
    with pytest.raises(ValueError, match="vazio"):
        parse_iptables_save("", "ipv4")


def test_marks_missing_forward_policy_as_unassessed():
    baseline = policy()
    del baseline["forward_policy"]

    result = analyze_iptables_saves(
        baseline,
        sample(),
        sample(),
    )

    assert "ipv4:forward" in result["summary"]["unassessed_hooks"]
    assert "ipv6:forward" in result["summary"]["unassessed_hooks"]
    assert result["status"] == "INCONCLUSIVE"
