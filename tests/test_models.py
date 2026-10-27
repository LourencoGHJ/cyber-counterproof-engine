import json
from pathlib import Path

from cce.models import validate_policy, validate_requirements


ROOT = Path(__file__).resolve().parents[1]


def load_example(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def test_repository_example_policy_and_requirements_are_valid():
    assert validate_policy(load_example("config/policy.json")) == []
    assert validate_requirements(load_example("config/requirements.json")) == []


def test_policy_validator_handles_unhashable_values_without_crashing():
    policy = {
        "policy_id": "malformed",
        "input_policy": [],
        "output_policy": {},
        "rules": [
            {
                "id": "bad-rule",
                "chain": [],
                "action": {},
                "protocol": ["tcp"],
                "source": ["192.0.2.0/24"],
                "destination_port": True,
                "service": "",
            }
        ],
    }

    errors = validate_policy(policy)

    assert len(errors) >= 7
    assert any("input_policy" in error for error in errors)
    assert any("protocol" in error for error in errors)
    assert any("source" in error for error in errors)


def test_policy_validator_rejects_non_object_input():
    assert validate_policy(["not", "a", "policy"]) == [
        "A política tem de ser um objeto JSON."
    ]


def test_requirements_validator_rejects_non_object_items():
    errors = validate_requirements(
        {"requirements": ["not-an-object"], "traffic_tests": []}
    )

    assert any("requirements[0] tem de ser um objeto" in error for error in errors)


def test_requirements_validator_rejects_malformed_traffic_test():
    errors = validate_requirements(
        {
            "requirements": [],
            "traffic_tests": [
                {
                    "id": "broken",
                    "source": "not-an-ip",
                    "destination_port": 70000,
                    "protocol": "sctp",
                    "service": "",
                    "expected": "execute",
                }
            ],
        }
    )

    assert any("source tem de ser um endereço IP válido" in error for error in errors)
    assert any("destination_port" in error for error in errors)
    assert any("protocol" in error for error in errors)
    assert any("service" in error for error in errors)
    assert any("expected" in error for error in errors)


def test_requirements_validator_rejects_invalid_severity():
    errors = validate_requirements(
        {
            "requirements": [
                {
                    "id": "REQ-1",
                    "type": "default_input_policy",
                    "expected": "drop",
                    "severity": ["critical"],
                }
            ],
            "traffic_tests": [],
        }
    )

    assert any("severity" in error for error in errors)


def test_forward_policy_accepts_only_accept_or_drop():
    from cce.models import validate_policy

    policy = {
        "policy_id": "forward-test",
        "input_policy": "drop",
        "output_policy": "accept",
        "forward_policy": "drop",
        "rules": [],
    }
    assert validate_policy(policy) == []

    policy["forward_policy"] = "reject"
    assert any(
        "forward_policy" in error
        for error in validate_policy(policy)
    )
