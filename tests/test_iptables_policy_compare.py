import json

from cce.iptables_policy_compare import compare_policy_rules_to_snapshots
from cce.iptables_save import analyze_iptables_saves


def baseline_rule(**overrides):
    rule = {
        "id": "allow-https-lab",
        "chain": "input",
        "action": "accept",
        "protocol": "tcp",
        "source": "192.0.2.0/24",
        "destination_port": 443,
        "service": "https",
    }
    rule.update(overrides)
    return rule


def policy(*rules):
    return {"policy_id": "test", "rules": list(rules)}


def snapshot(rule_lines, chain="INPUT"):
    return (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        f"{rule_lines}"
        "COMMIT\n"
    )


def compare(rule, text, family="ipv4"):
    return compare_policy_rules_to_snapshots(
        policy(rule),
        ((family, text),),
    )


def test_exact_supported_rule_is_matched_without_disclosing_selectors():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    item = report["comparisons"][0]
    assert item["status"] == "MATCHED"
    assert report["summary"]["rules_matched"] == 1
    assert report["summary"]["rules_semantically_compared"] == 1

    rendered = json.dumps(report, ensure_ascii=False)
    assert "192.0.2.0/24" not in rendered
    assert "443" not in rendered


def test_broader_accept_rule_is_reported_as_potential_exposure():
    text = snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
    report = compare(baseline_rule(), text)

    item = report["comparisons"][0]
    assert item["status"] == "BROADER_SCOPE"
    assert item["impact"] == "potential_exposure"
    assert report["summary"]["conclusive_rule_drifts"] == 1


def test_narrower_accept_rule_is_reported_as_coverage_gap():
    text = snapshot(
        "-A INPUT -s 192.0.2.10/32 -p tcp --dport 443 -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    item = report["comparisons"][0]
    assert item["status"] == "NARROWER_SCOPE"
    assert item["impact"] == "coverage_gap"


def test_action_mismatch_is_detected():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j DROP\n"
    )
    report = compare(baseline_rule(), text)

    assert report["comparisons"][0]["status"] == "ACTION_MISMATCH"
    assert report["comparisons"][0]["observed_action"] == "DROP"


def test_missing_rule_is_reported_when_chain_is_fully_interpretable():
    report = compare(baseline_rule(), snapshot(""))

    assert report["comparisons"][0]["status"] == "MISSING"
    assert report["summary"]["rules_missing"] == 1


def test_partial_rule_in_chain_prevents_proving_absence():
    text = snapshot(
        "-A INPUT -m recent --name cce --set -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    assert report["comparisons"][0]["status"] == "INCONCLUSIVE"
    assert "parcialmente interpretadas" in report["comparisons"][0]["reason"]


def test_extra_connection_state_selector_is_not_silently_ignored():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 "
        "-m conntrack --ctstate NEW -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    item = report["comparisons"][0]
    assert item["status"] == "INCONCLUSIVE"
    assert item["unmodelled_selectors"] == ["connection_states"]


def test_multiple_candidate_rules_are_ambiguous():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    assert report["comparisons"][0]["status"] == "INCONCLUSIVE"
    assert len(report["comparisons"][0]["observed_lines"]) == 2


def test_ipv4_specific_policy_rule_is_not_applicable_to_ipv6():
    text = snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
    report = compare(baseline_rule(), text, family="ipv6")

    assert report["comparisons"][0]["status"] == "NOT_APPLICABLE"



def full_policy(rule):
    return {
        "policy_id": "test-baseline",
        "input_policy": "drop",
        "output_policy": "accept",
        "rules": [rule],
    }


def test_semantic_comparison_is_integrated_into_iptables_save_analysis():
    ipv4 = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
    )
    ipv6 = snapshot("")

    result = analyze_iptables_saves(
        full_policy(baseline_rule()),
        ipv4,
        ipv6,
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["rules_semantically_compared"] == 1
    assert result["summary"]["semantic_rule_matches"] == 1
    assert result["summary"]["semantic_rule_drifts"] == 0
    statuses = [
        item["status"]
        for item in result["rule_policy_comparison"]["comparisons"]
    ]
    assert statuses == ["MATCHED", "NOT_APPLICABLE"]


def test_semantic_rule_drift_changes_integrated_status_to_drift():
    ipv4 = snapshot("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
    ipv6 = snapshot("")

    result = analyze_iptables_saves(
        full_policy(baseline_rule()),
        ipv4,
        ipv6,
    )

    assert result["status"] == "DRIFT"
    assert result["summary"]["semantic_rule_drifts"] == 1
    assert result["rule_policy_comparison"]["findings"][0]["status"] == (
        "BROADER_SCOPE"
    )



def test_user_chain_transfer_prevents_proving_rule_absence():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP-SERVICES - [0:0]\n"
        "-A INPUT -j APP-SERVICES\n"
        "-A APP-SERVICES -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )
    report = compare(baseline_rule(), text)

    assert report["comparisons"][0]["status"] == "INCONCLUSIVE"
    assert "não segue esse fluxo" in report["comparisons"][0]["reason"]



def test_missing_reject_rule_is_reported_as_potential_exposure():
    report = compare(
        baseline_rule(action="reject"),
        snapshot(""),
    )

    assert report["comparisons"][0]["status"] == "MISSING"
    assert report["comparisons"][0]["impact"] == "potential_exposure"


def test_reject_rule_with_broader_scope_is_reported_as_broader_blocking():
    text = snapshot("-A INPUT -p tcp --dport 443 -j REJECT\n")
    report = compare(baseline_rule(action="reject"), text)

    assert report["comparisons"][0]["status"] == "BROADER_SCOPE"
    assert report["comparisons"][0]["impact"] == "broader_blocking_than_policy"
