"""Comparação conservadora de políticas com um snapshot JSON do nftables."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from cce.chain_graph import analyze_chain_graph


HOOK_FIELDS = {
    "input": "input_policy",
    "output": "output_policy",
    "forward": "forward_policy",
}

SUPPORTED_POLICIES = {"accept", "drop"}


def analyze_live_ruleset(
    policy: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Compara políticas de base chains sem alegar interpretar todas as regras."""
    if not isinstance(policy, dict):
        raise ValueError("A política esperada tem de ser um objeto JSON.")

    if not isinstance(snapshot, dict):
        raise ValueError("O snapshot nftables tem de ser um objeto JSON.")

    elements = snapshot.get("nftables")
    if not isinstance(elements, list):
        raise ValueError("O snapshot não contém uma lista nftables válida.")

    # Só comparamos hooks para os quais a política declara um valor esperado.
    expected_policies = {
        hook: policy[field]
        for hook, field in HOOK_FIELDS.items()
        if field in policy
    }

    if not expected_policies:
        raise ValueError("A política não declara políticas de base chains.")

    for hook, expected in expected_policies.items():
        if expected not in SUPPORTED_POLICIES:
            raise ValueError(
                f"A política esperada para {hook} tem de ser "
                "'accept' ou 'drop'."
            )

    rule_counts: Counter[tuple[str, str, str]] = Counter()
    expression_kinds: Counter[str] = Counter()
    rules_total = 0

    for index, element in enumerate(elements):
        if not isinstance(element, dict) or not element:
            raise ValueError(
                f"Elemento nftables inválido no índice {index}."
            )

        if "rule" not in element:
            continue

        rule = element["rule"]
        if not isinstance(rule, dict):
            raise ValueError(
                f"Regra nftables inválida no índice {index}."
            )

        key = (
            str(rule.get("family", "?")),
            str(rule.get("table", "?")),
            str(rule.get("chain", "?")),
        )
        rule_counts[key] += 1
        rules_total += 1

        expressions = rule.get("expr", [])
        if not isinstance(expressions, list):
            expression_kinds["invalid_expr_list"] += 1
            continue

        for expression in expressions:
            if isinstance(expression, dict) and expression:
                for kind in expression:
                    expression_kinds[str(kind)] += 1
            else:
                expression_kinds["unknown_expression"] += 1

    base_chains: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    observed_hooks: set[str] = set()

    for index, element in enumerate(elements):
        if "chain" not in element:
            continue

        chain = element["chain"]
        if not isinstance(chain, dict):
            raise ValueError(
                f"Chain nftables inválida no índice {index}."
            )

        hook = chain.get("hook")
        if hook not in HOOK_FIELDS:
            continue

        observed_hooks.add(hook)

        family = str(chain.get("family", "?"))
        table = str(chain.get("table", "?"))
        name = str(chain.get("name", "?"))
        expected = expected_policies.get(hook)

        # A ausência de policy numa base chain equivale à política accept.
        observed = chain.get("policy", "accept")

        if expected is None or observed not in SUPPORTED_POLICIES:
            policy_match = None
        else:
            policy_match = observed == expected

        entry = {
            "family": family,
            "table": table,
            "chain": name,
            "hook": hook,
            "expected_policy": expected,
            "observed_policy": observed,
            "policy_match": policy_match,
            "rule_count": rule_counts[(family, table, name)],
        }

        if expected is None:
            entry["note"] = (
                f"A política não declara {HOOK_FIELDS[hook]}; "
                "esta chain não foi comparada."
            )

        base_chains.append(entry)

        if policy_match is False:
            severity = (
                "high"
                if hook == "input"
                and expected == "drop"
                and observed == "accept"
                else "medium"
            )
            findings.append({
                "code": "CCE-LIVE-BASE-POLICY-MISMATCH",
                "severity": severity,
                "family": family,
                "table": table,
                "chain": name,
                "hook": hook,
                "expected": expected,
                "observed": observed,
                "detail": (
                    "A política por omissão desta base chain "
                    "difere da política declarada."
                ),
            })

    missing_hooks = sorted(set(expected_policies) - observed_hooks)
    unassessed_hooks = sorted(set(HOOK_FIELDS) - set(expected_policies))

    chain_graph = analyze_chain_graph(snapshot)

    matched_count = sum(
        entry["policy_match"] is True for entry in base_chains
    )
    unresolved_count = sum(
        entry["policy_match"] is None for entry in base_chains
    )

    # Mesmo sem divergências, as regras individuais não foram interpretadas.
    structural_dangling = chain_graph["summary"]["dangling_targets"]
    status = (
        "DRIFT"
        if findings or structural_dangling
        else "INCONCLUSIVE"
    )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "scope": "base_chain_policies_only",
        "summary": {
            "base_chains": len(base_chains),
            "base_policies_matched": matched_count,
            "base_policies_unresolved": unresolved_count,
            "base_policy_mismatches": len(findings),
            "rules_total": rules_total,
            "rules_semantically_compared": 0,
            "missing_hooks": missing_hooks,
            "unassessed_hooks": unassessed_hooks,
            "structural_dangling_targets": structural_dangling,
            "chains_without_explicit_path": chain_graph["summary"]["chains_without_explicit_path"],
            "rules_with_xt": chain_graph["summary"]["rules_with_xt"],
        },
        "base_chains": base_chains,
        "findings": findings,
        "chain_graph": chain_graph,
        "expression_kinds": dict(sorted(expression_kinds.items())),
        "limitations": [
            "A análise compara apenas políticas por omissão das base chains.",
            "As regras individuais e a sua ordem não são comparadas.",
            "Não é avaliada a semântica completa dos saltos entre chains.",
            "Expressões de compatibilidade xt não são interpretadas.",
            "A acessibilidade considera apenas referências explícitas jump/goto.",
            "Hooks sem política declarada ficam por avaliar.",
            "INCONCLUSIVE não significa que a firewall seja segura ou insegura.",
            "O snapshot pode estar desatualizado relativamente ao estado atual.",
            "Não foi aplicada, removida ou modificada qualquer regra.",
        ],
    }
