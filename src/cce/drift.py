
"""Comparação declarativa de políticas para deteção de divergências."""
from __future__ import annotations

from typing import Any


def _rule_signature(rule: dict[str, Any]) -> tuple[Any, ...]:
    """Devolve os atributos que determinam o comportamento declarado da regra."""
    return (
        rule.get("chain"),
        rule.get("action"),
        rule.get("protocol"),
        rule.get("source", "any"),
        rule.get("destination_port"),
        rule.get("service"),
    )


def compare_policies(
    expected_policy: dict[str, Any],
    observed_policy: dict[str, Any],
) -> dict[str, Any]:
    """Compara políticas declarativas sem alterar o sistema operativo.

    A comparação usa o ID como identidade da regra e os atributos
    comportamentais para identificar regras modificadas.
    """
    expected_rules = expected_policy.get("rules", [])
    observed_rules = observed_policy.get("rules", [])

    if not isinstance(expected_rules, list) or not isinstance(observed_rules, list):
        raise ValueError("'rules' tem de ser uma lista em ambas as políticas.")

    def index_rules(rules: list[Any], label: str) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        for position, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"{label}[{position}] tem de ser um objeto.")
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(f"{label}[{position}] não tem um ID válido.")
            if rule_id in indexed:
                raise ValueError(f"ID duplicado em {label}: {rule_id}.")
            indexed[rule_id] = rule
        return indexed

    expected = index_rules(expected_rules, "expected.rules")
    observed = index_rules(observed_rules, "observed.rules")

    findings: list[dict[str, Any]] = []

    for rule_id in sorted(expected.keys() - observed.keys()):
        findings.append({
            "code": "CCE-DRIFT-RULE-MISSING",
            "severity": "high",
            "rule_id": rule_id,
            "expected": expected[rule_id],
            "observed": None,
        })

    for rule_id in sorted(observed.keys() - expected.keys()):
        findings.append({
            "code": "CCE-DRIFT-RULE-UNEXPECTED",
            "severity": "medium",
            "rule_id": rule_id,
            "expected": None,
            "observed": observed[rule_id],
        })

    for rule_id in sorted(expected.keys() & observed.keys()):
        expected_signature = _rule_signature(expected[rule_id])
        observed_signature = _rule_signature(observed[rule_id])

        if expected_signature != observed_signature:
            findings.append({
                "code": "CCE-DRIFT-RULE-MISMATCH",
                "severity": "high",
                "rule_id": rule_id,
                "expected": expected[rule_id],
                "observed": observed[rule_id],
            })

    return {
        "expected_policy_id": expected_policy.get("policy_id", "unknown"),
        "observed_policy_id": observed_policy.get("policy_id", "unknown"),
        "status": "PASS" if not findings else "DRIFT",
        "summary": {
            "expected_rules": len(expected),
            "observed_rules": len(observed),
            "findings_total": len(findings),
        },
        "findings": findings,
        "limitations": [
            "A comparação é declarativa e não inspeciona a firewall real.",
            "A identidade das regras é determinada pelo respetivo ID.",
            "A comparação não avalia a ordem das regras nem a semântica completa do nftables.",
        ],
    }
