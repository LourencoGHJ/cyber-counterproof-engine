import pytest

from cce.live import analyze_live_ruleset


def make_policy():
    return {
        "input_policy": "drop",
        "output_policy": "accept",
        "forward_policy": "drop",
    }


def make_snapshot(input_policy="drop", output_policy="accept"):
    return {
        "nftables": [
            {
                "chain": {
                    "family": "ip",
                    "table": "filter",
                    "name": "INPUT",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                    "policy": input_policy,
                }
            },
            {
                "chain": {
                    "family": "ip",
                    "table": "filter",
                    "name": "OUTPUT",
                    "type": "filter",
                    "hook": "output",
                    "prio": 0,
                    "policy": output_policy,
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "filter",
                    "chain": "INPUT",
                    "expr": [
                        {"counter": {"packets": 2, "bytes": 80}},
                        {"jump": {"target": "ufw-before-input"}},
                    ],
                }
            },
        ]
    }


def test_matching_base_policies_remain_inconclusive():
    result = analyze_live_ruleset(make_policy(), make_snapshot())

    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["base_policy_mismatches"] == 0
    assert result["summary"]["rules_semantically_compared"] == 0


def test_detects_input_base_policy_mismatch():
    result = analyze_live_ruleset(
        make_policy(),
        make_snapshot(input_policy="accept"),
    )

    assert result["status"] == "DRIFT"
    assert result["summary"]["base_policy_mismatches"] == 1

    finding = result["findings"][0]
    assert finding["code"] == "CCE-LIVE-BASE-POLICY-MISMATCH"
    assert finding["hook"] == "input"
    assert finding["expected"] == "drop"
    assert finding["observed"] == "accept"
    assert finding["severity"] == "high"


def test_reports_missing_hooks_without_claiming_pass():
    snapshot = {
        "nftables": [
            {
                "chain": {
                    "family": "ip",
                    "table": "filter",
                    "name": "INPUT",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                    "policy": "drop",
                }
            }
        ]
    }

    result = analyze_live_ruleset(make_policy(), snapshot)

    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["missing_hooks"] == ["forward", "output"]


def test_missing_base_chain_policy_defaults_to_accept():
    snapshot = {
        "nftables": [
            {
                "chain": {
                    "family": "ip",
                    "table": "filter",
                    "name": "INPUT",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                }
            }
        ]
    }

    result = analyze_live_ruleset(make_policy(), snapshot)

    assert result["status"] == "DRIFT"
    assert result["findings"][0]["observed"] == "accept"


def test_counts_expression_types_without_interpreting_them():
    result = analyze_live_ruleset(make_policy(), make_snapshot())

    assert result["expression_kinds"]["counter"] == 1
    assert result["expression_kinds"]["jump"] == 1
    assert result["summary"]["rules_total"] == 1


def test_rejects_snapshot_without_nftables_list():
    with pytest.raises(ValueError, match="lista nftables"):
        analyze_live_ruleset(make_policy(), {})


def test_rejects_unsupported_expected_base_policy():
    policy = make_policy()
    policy["input_policy"] = "reject"

    with pytest.raises(ValueError, match="accept.*drop"):
        analyze_live_ruleset(policy, make_snapshot())



def test_forward_base_chains_are_compared_when_declared():
    snapshot = make_snapshot()
    snapshot["nftables"].append({
        "chain": {
            "family": "ip",
            "table": "filter",
            "name": "FORWARD",
            "type": "filter",
            "hook": "forward",
            "prio": 0,
            "policy": "drop",
        }
    })

    result = analyze_live_ruleset(make_policy(), snapshot)

    assert result["status"] == "INCONCLUSIVE"
    assert result["summary"]["unassessed_hooks"] == []
    assert result["summary"]["base_policies_matched"] == 3

    forward = next(
        chain for chain in result["base_chains"]
        if chain["hook"] == "forward"
    )
    assert forward["expected_policy"] == "drop"
    assert forward["observed_policy"] == "drop"
    assert forward["policy_match"] is True


def test_forward_remains_unassessed_when_policy_is_not_declared():
    policy = make_policy()
    del policy["forward_policy"]

    snapshot = make_snapshot()
    snapshot["nftables"].append({
        "chain": {
            "family": "ip",
            "table": "filter",
            "name": "FORWARD",
            "type": "filter",
            "hook": "forward",
            "prio": 0,
            "policy": "drop",
        }
    })

    result = analyze_live_ruleset(policy, snapshot)

    assert result["summary"]["unassessed_hooks"] == ["forward"]

    forward = next(
        chain for chain in result["base_chains"]
        if chain["hook"] == "forward"
    )
    assert forward["policy_match"] is None
