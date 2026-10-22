
import pytest

from cce.drift import compare_policies


def policy(policy_id, rules):
    return {"policy_id": policy_id, "rules": rules}


def rule(rule_id, action="accept", port=22):
    return {
        "id": rule_id,
        "chain": "input",
        "action": action,
        "protocol": "tcp",
        "source": "192.0.2.10/32",
        "destination_port": port,
        "service": "ssh",
    }


def test_identical_policies_pass():
    result = compare_policies(
        policy("expected", [rule("ssh")]),
        policy("observed", [rule("ssh")]),
    )
    assert result["status"] == "PASS"
    assert result["summary"]["findings_total"] == 0


def test_missing_rule_is_detected():
    result = compare_policies(
        policy("expected", [rule("ssh")]),
        policy("observed", []),
    )
    assert result["status"] == "DRIFT"
    assert result["findings"][0]["code"] == "CCE-DRIFT-RULE-MISSING"


def test_unexpected_rule_is_detected():
    result = compare_policies(
        policy("expected", []),
        policy("observed", [rule("unexpected")]),
    )
    assert result["findings"][0]["code"] == "CCE-DRIFT-RULE-UNEXPECTED"


def test_changed_rule_is_detected():
    result = compare_policies(
        policy("expected", [rule("ssh", action="accept")]),
        policy("observed", [rule("ssh", action="drop")]),
    )
    assert result["findings"][0]["code"] == "CCE-DRIFT-RULE-MISMATCH"


def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(ValueError, match="ID duplicado"):
        compare_policies(
            policy("expected", [rule("ssh"), rule("ssh")]),
            policy("observed", []),
        )


def test_invalid_rule_is_rejected():
    with pytest.raises(ValueError, match="objeto"):
        compare_policies(
            policy("expected", [None]),
            policy("observed", []),
        )
