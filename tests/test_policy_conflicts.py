import json

from cce.policy_conflicts import analyze_iptables_rule_conflicts


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


def analyze(rules="", extra_chains="", extra_tables=""):
    return analyze_iptables_rule_conflicts(
        snapshot(rules, extra_chains, extra_tables),
        "ipv4",
    )


def codes(result):
    return [finding["code"] for finding in result["findings"]]


def test_detects_exact_duplicate_terminal_rule():
    result = analyze(
        "-A INPUT -p tcp --dport 22 -j DROP\n"
        "-A INPUT -p tcp --dport 22 -j DROP\n"
    )

    assert codes(result) == ["DUPLICATE_RULE"]
    assert result["summary"]["duplicate_rules"] == 1
    finding = result["findings"][0]
    assert finding["earlier_line"] < finding["later_line"]
    assert finding["certainty"] == "proven"


def test_detects_redundant_rule_fully_covered_by_same_verdict():
    result = analyze(
        "-A INPUT -p tcp -j ACCEPT\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
    )

    assert codes(result) == ["REDUNDANT_RULE"]
    assert result["summary"]["redundant_rules"] == 1


def test_detects_shadowed_rule_with_conflicting_verdict():
    result = analyze(
        "-A INPUT -p tcp -j DROP\n"
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
    )

    assert codes(result) == ["SHADOWED_RULE"]
    finding = result["findings"][0]
    assert finding["earlier_verdict"] == "DROP"
    assert finding["later_verdict"] == "ACCEPT"
    assert finding["severity"] == "high"
    assert finding["certainty"] == "proven"


def test_detects_potential_overlap_when_neither_rule_covers_the_other():
    result = analyze(
        "-A INPUT -p tcp --dport 443 -j ACCEPT\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp -j DROP\n"
    )

    assert codes(result) == ["OVERLAPPING_VERDICTS"]
    assert result["findings"][0]["certainty"] == "potential"


def test_does_not_report_disjoint_source_networks_as_overlapping():
    result = analyze(
        "-A INPUT -s 192.0.2.0/24 -p tcp -j ACCEPT\n"
        "-A INPUT -s 203.0.113.0/24 -p tcp -j DROP\n"
    )

    assert result["findings"] == []
    assert result["summary"]["findings_total"] == 0


def test_does_not_report_different_protocols_as_overlapping():
    result = analyze(
        "-A INPUT -p tcp -j ACCEPT\n"
        "-A INPUT -p udp -j DROP\n"
    )

    assert result["findings"] == []


def test_proves_shadowing_for_narrower_source_subnet_and_port():
    result = analyze(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j DROP\n"
        "-A INPUT -s 192.0.2.10/32 -p tcp --dport 443 -j ACCEPT\n"
    )

    assert codes(result) == ["SHADOWED_RULE"]


def test_detects_interface_prefix_overlap():
    result = analyze(
        "-A INPUT -i eth+ -p tcp -j ACCEPT\n"
        "-A INPUT -i eth0+ -p tcp -j DROP\n"
    )

    assert codes(result) == ["SHADOWED_RULE"]


def test_does_not_report_disjoint_interface_prefixes():
    result = analyze(
        "-A INPUT -i eth+ -p tcp -j ACCEPT\n"
        "-A INPUT -i wlan+ -p tcp -j DROP\n"
    )

    assert result["findings"] == []


def test_detects_non_overlapping_destination_port_ranges():
    result = analyze(
        "-A INPUT -p tcp --dport 1:100 -j ACCEPT\n"
        "-A INPUT -p tcp --dport 101:200 -j DROP\n"
    )

    assert result["findings"] == []


def test_detects_disjoint_connection_states():
    result = analyze(
        "-A INPUT -p tcp -m conntrack --ctstate NEW -j ACCEPT\n"
        "-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED -j DROP\n"
    )

    assert result["findings"] == []


def test_detects_disjoint_tcp_flag_comparisons():
    result = analyze(
        "-A INPUT -p tcp --tcp-flags SYN,ACK SYN -j ACCEPT\n"
        "-A INPUT -p tcp --tcp-flags SYN,ACK ACK -j DROP\n"
    )

    assert result["findings"] == []


def test_does_not_compare_rules_in_different_chains():
    result = analyze(
        "-A INPUT -p tcp -j ACCEPT\n"
        "-A custom-chain -p tcp -j DROP\n",
        extra_chains=":custom-chain - [0:0]\n",
    )

    assert result["findings"] == []


def test_skips_partially_interpreted_rules_and_counts_them():
    result = analyze(
        "-A INPUT -p tcp -m recent --name ssh --set -j DROP\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
    )

    assert result["findings"] == []
    assert result["summary"]["partial_rules_skipped"] == 1
    assert result["summary"]["terminal_rules_analyzed"] == 1


def test_ignores_non_terminal_targets_for_conflict_conclusions():
    result = analyze(
        "-A INPUT -p tcp -j LOG\n"
        "-A INPUT -p tcp -j ACCEPT\n"
    )

    assert result["findings"] == []
    assert result["summary"]["terminal_rules_analyzed"] == 1


def test_finding_report_does_not_include_packet_network_values():
    result = analyze(
        "-A INPUT -s 192.0.2.0/24 -p tcp -j DROP\n"
        "-A INPUT -s 192.0.2.10/32 -p tcp -j ACCEPT\n"
    )

    rendered = json.dumps(result, ensure_ascii=False)
    assert "192.0.2.0/24" not in rendered
    assert "192.0.2.10/32" not in rendered


def test_negated_tcp_syn_rules_are_analyzed_using_effective_condition():
    result = analyze(
        "-A INPUT -p tcp --syn -j ACCEPT\n"
        "-A INPUT -p tcp ! --syn -j DROP\n"
    )

    assert result["findings"] == []



def test_counts_user_chain_transfers_as_non_terminal_rules_skipped():
    result = analyze(
        "-A INPUT -j ssh-check\n",
        extra_chains=":ssh-check - [0:0]\n",
    )

    assert result["summary"]["terminal_rules_analyzed"] == 0
    assert result["summary"]["non_terminal_rules_skipped"] == 1
    assert result["findings"] == []



def test_negated_fragment_selector_is_disjoint_from_fragment_only_rule():
    result = analyze(
        "-A INPUT -f -p tcp -j DROP\n"
        "-A INPUT ! -f -p tcp -j ACCEPT\n"
    )

    assert result["findings"] == []



def test_does_not_use_proven_shadowed_rule_as_later_conflict_evidence():
    result = analyze(
        "-A INPUT -s 192.0.2.0/24 -p tcp -j ACCEPT\n"
        "-A INPUT -s 192.0.2.10/32 -p tcp -j DROP\n"
        "-A INPUT -s 192.0.0.0/16 -p tcp --dport 443 -j REJECT\n"
    )

    assert codes(result) == [
        "SHADOWED_RULE",
        "OVERLAPPING_VERDICTS",
    ]
    overlap = next(
        finding for finding in result["findings"]
        if finding["code"] == "OVERLAPPING_VERDICTS"
    )
    assert overlap["earlier_line"] == 5
    assert overlap["later_line"] == 7



def test_detects_terminal_rules_with_impossible_tcp_flag_conditions():
    result = analyze(
        "-A INPUT -p tcp ! --tcp-flags NONE NONE -j DROP\n"
        "-A INPUT -p tcp --syn --tcp-flags SYN,ACK ACK -j ACCEPT\n"
    )

    assert result["summary"]["unmatchable_terminal_rules"] == 2
    assert result["summary"]["terminal_rules_analyzed"] == 0
    assert result["summary"]["non_terminal_rules_skipped"] == 0
    assert [item["code"] for item in result["findings"]] == [
        "UNMATCHABLE_RULE",
        "UNMATCHABLE_RULE",
    ]
    assert all(item["certainty"] == "proven" for item in result["findings"])
