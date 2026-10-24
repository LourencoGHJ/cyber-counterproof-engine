import copy
import json
from pathlib import Path

from cce.engine import analyze, evaluate_traffic
from cce.models import validate_policy, validate_requirements

ROOT = Path(__file__).resolve().parents[1]


def load_examples():
    policy = json.loads((ROOT / "config/policy.json").read_text(encoding="utf-8"))
    requirements = json.loads((ROOT / "config/requirements.json").read_text(encoding="utf-8"))
    return policy, requirements


def test_example_policy_is_valid():
    policy, requirements = load_examples()
    assert validate_policy(policy) == []
    assert validate_requirements(requirements) == []


def test_baseline_passes_high_severity_checks():
    policy, requirements = load_examples()
    result = analyze(policy, requirements)
    assert result["status"] == "PASS"
    assert result["summary"]["tests_failed"] == 0


def test_permissive_input_policy_is_detected():
    policy, requirements = load_examples()
    policy["input_policy"] = "accept"
    result = analyze(policy, requirements)
    assert result["status"] == "FAIL"
    assert any(f["code"] == "CCE-INPUT-DEFAULT-PERMIT" for f in result["findings"])


def test_global_ssh_exposure_is_detected():
    policy, requirements = load_examples()
    policy["rules"].append({
        "id": "bad-ssh",
        "chain": "input",
        "action": "accept",
        "protocol": "tcp",
        "source": "any",
        "destination_port": 22,
        "service": "ssh",
        "description": "Regra deliberadamente insegura para teste."
    })
    result = analyze(policy, requirements)
    assert any(f["code"] == "CCE-SERVICE-GLOBAL-EXPOSURE" for f in result["findings"])


def test_traffic_model_matches_source_network():
    policy, _ = load_examples()
    assert evaluate_traffic(policy, {
        "source": "192.0.2.10", "destination_port": 22,
        "protocol": "tcp", "service": "ssh"
    }) == "accept"
    assert evaluate_traffic(policy, {
        "source": "198.51.100.25", "destination_port": 22,
        "protocol": "tcp", "service": "ssh"
    }) == "drop"


def test_duplicate_rule_ids_are_rejected():
    policy, _ = load_examples()
    policy["rules"].append(copy.deepcopy(policy["rules"][0]))
    assert any("duplicado" in err for err in validate_policy(policy))
