import json

from cce.iptables_policy_compare import compare_policy_rules_to_snapshots
from cce.iptables_save import analyze_iptables_saves
from cce.models import validate_policy


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


def established_rule(**overrides):
    rule = baseline_rule(
        protocol="any",
        source="any",
        destination_port=None,
        service="established_related",
    )
    rule["connection_states"] = ["ESTABLISHED", "RELATED"]
    rule.update(overrides)
    return rule


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


def test_connection_state_selector_is_compared_when_policy_is_unrestricted():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 "
        "-m conntrack --ctstate NEW -j ACCEPT\n"
    )
    report = compare(baseline_rule(), text)

    item = report["comparisons"][0]
    assert item["status"] == "NARROWER_SCOPE"
    assert item["unmodelled_selectors"] == []


def test_exact_connection_state_set_is_matched():
    text = snapshot(
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
    )
    report = compare(established_rule(), text)

    assert report["comparisons"][0]["status"] == "MATCHED"


def test_narrower_connection_state_set_is_a_coverage_gap():
    text = snapshot(
        "-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT\n"
    )
    item = compare(established_rule(), text)["comparisons"][0]

    assert item["status"] == "NARROWER_SCOPE"
    assert item["impact"] == "coverage_gap"


def test_broader_connection_state_set_is_a_potential_exposure():
    text = snapshot(
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED,NEW -j ACCEPT\n"
    )
    item = compare(established_rule(), text)["comparisons"][0]

    assert item["status"] == "BROADER_SCOPE"
    assert item["impact"] == "potential_exposure"


def test_missing_observed_state_filter_is_broader_than_policy():
    item = compare(established_rule(), snapshot("-A INPUT -j ACCEPT\n"))[
        "comparisons"
    ][0]

    assert item["status"] == "BROADER_SCOPE"


def test_disjoint_connection_state_set_is_reported_as_missing():
    text = snapshot("-A INPUT -m conntrack --ctstate NEW -j ACCEPT\n")
    item = compare(established_rule(), text)["comparisons"][0]

    assert item["status"] == "MISSING"


def test_partially_overlapping_connection_state_sets_are_reported():
    text = snapshot(
        "-A INPUT -m conntrack --ctstate ESTABLISHED,NEW -j ACCEPT\n"
    )
    item = compare(established_rule(), text)["comparisons"][0]

    assert item["status"] == "PARTIAL_OVERLAP"


def test_legacy_state_match_module_is_compared():
    text = snapshot(
        "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
    )

    assert compare(established_rule(), text)["comparisons"][0]["status"] == (
        "MATCHED"
    )


def test_negated_connection_state_selector_remains_inconclusive():
    text = snapshot(
        "-A INPUT -m conntrack ! --ctstate NEW -j ACCEPT\n"
    )
    item = compare(established_rule(), text)["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"
    assert "negated_conditions" in item["unmodelled_selectors"]


def test_policy_connection_states_validation():
    valid = {
        "policy_id": "state-test",
        "input_policy": "drop",
        "output_policy": "accept",
        "rules": [established_rule()],
    }
    assert validate_policy(valid) == []

    invalid_values = [
        [],
        "ESTABLISHED",
        ["UNKNOWN"],
        ["NEW", "NEW"],
        [None],
    ]
    for states in invalid_values:
        invalid = {
            **valid,
            "rules": [{**established_rule(), "connection_states": states}],
        }
        assert any(
            "connection_states" in error
            for error in validate_policy(invalid)
        )


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

    item = report["comparisons"][0]
    assert item["status"] == "BROADER_SCOPE"
    assert item["observed_action"] == "ACCEPT"
    assert [step["chain"] for step in item["flow_path"]] == [
        "INPUT",
        "APP-SERVICES",
    ]



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



def test_return_target_does_not_masquerade_as_user_chain_transfer():
    report = compare(
        baseline_rule(),
        snapshot("-A INPUT -j RETURN\n"),
    )

    assert report["comparisons"][0]["status"] == "MISSING"



def test_comparator_follows_nested_jump_and_goto_with_exact_scope():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        ":LEAF - [0:0]\n"
        "-A INPUT -j APP\n"
        "-A APP -g LEAF\n"
        "-A LEAF -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "MATCHED"
    assert [step["operation"] for step in item["flow_path"]] == [
        "jump",
        "goto",
        "jump",
    ]
    assert [step["chain"] for step in item["flow_path"]] == [
        "INPUT",
        "APP",
        "LEAF",
    ]


def test_comparator_resumes_caller_after_user_chain_return():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -j APP\n"
        "-A APP -j RETURN\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "MATCHED"
    assert [step["target"] for step in item["flow_path"]] == [
        "APP",
        "RETURN",
        "ACCEPT",
    ]


def test_goto_return_skips_remainder_of_user_chain():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":OUTER - [0:0]\n"
        ":INNER - [0:0]\n"
        "-A INPUT -j OUTER\n"
        "-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "-A OUTER -g INNER\n"
        "-A OUTER -s 192.0.2.0/24 -p tcp --dport 443 -j DROP\n"
        "-A INNER -j RETURN\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "MATCHED"
    assert not any(
        step["chain"] == "OUTER" and step["target"] == "DROP"
        for step in item["flow_path"]
    )
    assert item["flow_path"][-1]["target"] == "ACCEPT"


def test_partial_user_chain_transfer_remains_inconclusive():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -s 192.0.2.0/25 -j APP\n"
        "-A APP -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"
    assert "parte do âmbito" in item["reason"]


def test_recursive_user_chain_remains_inconclusive():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -j APP\n"
        "-A APP -j APP\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"
    assert "recursão" in item["reason"]


def test_unmodelled_interface_in_user_chain_remains_inconclusive():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -j APP\n"
        "-A APP -i eth+ -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"
    assert item["unmodelled_selectors"] == ["input_interface_pattern"]

def test_comparator_resolves_lowercase_user_chain_names():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":app-services - [0:0]\n"
        "-A INPUT -j app-services\n"
        "-A app-services -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "MATCHED"
    assert item["observed_action"] == "ACCEPT"
    assert [step["chain"] for step in item["flow_path"]] == [
        "INPUT",
        "app-services",
    ]
    assert item["flow_path"][0]["target"] == "app-services"

def test_policy_accepts_exact_interface_selectors():
    valid = {
        "policy_id": "interface-test",
        "input_policy": "drop",
        "output_policy": "accept",
        "rules": [
            baseline_rule(input_interface="lo", output_interface="wan0")
        ],
    }

    assert validate_policy(valid) == []


def test_policy_rejects_wildcard_or_invalid_interface_names():
    for field, value in (
        ("input_interface", "eth+"),
        ("output_interface", "invalid interface"),
        ("input_interface", "x" * 16),
        ("output_interface", ""),
    ):
        invalid = {
            "policy_id": "interface-test",
            "input_policy": "drop",
            "output_policy": "accept",
            "rules": [baseline_rule(**{field: value})],
        }

        errors = validate_policy(invalid)
        assert any(field in error for error in errors)


def test_exact_input_interface_is_matched():
    text = snapshot(
        "-A INPUT -i lo -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
    )

    item = compare(
        baseline_rule(input_interface="lo"),
        text,
    )["comparisons"][0]

    assert item["status"] == "MATCHED"


def test_observed_input_interface_narrows_unrestricted_policy():
    text = snapshot(
        "-A INPUT -i lo -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "NARROWER_SCOPE"


def test_missing_observed_interface_is_broader_than_policy():
    text = snapshot(
        "-A INPUT -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
    )

    item = compare(
        baseline_rule(input_interface="lo"),
        text,
    )["comparisons"][0]

    assert item["status"] == "BROADER_SCOPE"


def test_different_input_interface_does_not_match():
    text = snapshot(
        "-A INPUT -i eth0 -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
    )

    item = compare(
        baseline_rule(input_interface="lo"),
        text,
    )["comparisons"][0]

    assert item["status"] == "MISSING"


def test_exact_output_interface_is_matched():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        "-A OUTPUT -o wan0 -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(
        baseline_rule(
            chain="output",
            source="any",
            output_interface="wan0",
        ),
        text,
    )["comparisons"][0]

    assert item["status"] == "MATCHED"


def test_exact_input_interface_is_combined_across_user_chain():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -i lo -j APP\n"
        "-A APP -s 192.0.2.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(
        baseline_rule(input_interface="lo"),
        text,
    )["comparisons"][0]

    assert item["status"] == "MATCHED"


def test_conflicting_interfaces_across_user_chain_remain_inconclusive():
    text = (
        "*filter\n"
        ":INPUT DROP [0:0]\n"
        ":OUTPUT ACCEPT [0:0]\n"
        ":FORWARD DROP [0:0]\n"
        ":APP - [0:0]\n"
        "-A INPUT -i lo -j APP\n"
        "-A APP -i eth0 -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )

    item = compare(
        baseline_rule(input_interface="lo"),
        text,
    )["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"


def test_wildcard_input_interface_remains_inconclusive():
    text = snapshot(
        "-A INPUT -i eth+ -s 192.0.2.0/24 "
        "-p tcp --dport 443 -j ACCEPT\n"
    )

    item = compare(baseline_rule(), text)["comparisons"][0]

    assert item["status"] == "INCONCLUSIVE"
    assert "input_interface_pattern" in item["unmodelled_selectors"]
