"""Conservative comparison of declarative policy rules with iptables-save IR.

Only fields represented by the current policy schema are compared:
chain, action, protocol, source network and destination port. Additional
selectors in observed rules are not silently ignored; they make the result
inconclusive because the current policy schema cannot express them.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from cce.iptables_ir import RuleIR, parse_iptables_rules_ir


TERMINAL_VERDICTS = {"ACCEPT", "DROP", "REJECT"}
CONCLUSIVE_STATUSES = {
    "MATCHED",
    "MISSING",
    "ACTION_MISMATCH",
    "BROADER_SCOPE",
    "NARROWER_SCOPE",
    "PARTIAL_OVERLAP",
}


def _network_relation(expected: str, observed: str | None) -> str:
    """Compare observed source coverage with the policy's expected network."""
    if expected == "any":
        return "equal" if observed is None else "observed_subset"

    expected_network = ipaddress.ip_network(expected, strict=False)
    if observed is None:
        return "observed_superset"

    observed_network = ipaddress.ip_network(observed, strict=False)
    if observed_network == expected_network:
        return "equal"
    if observed_network.subnet_of(expected_network):
        return "observed_subset"
    if expected_network.subnet_of(observed_network):
        return "observed_superset"
    if observed_network.overlaps(expected_network):
        return "partial"
    return "disjoint"


def _protocol_relation(expected: str, observed: str | None) -> str:
    expected_any = expected == "any"
    observed_any = observed in (None, "all")

    if expected_any and observed_any:
        return "equal"
    if expected_any:
        return "observed_subset"
    if observed_any:
        return "observed_superset"
    return "equal" if expected == observed else "disjoint"


def _ranges_overlap(
    left: Iterable[tuple[int, int]],
    right: Iterable[tuple[int, int]],
) -> bool:
    return any(
        first_a <= last_b and first_b <= last_a
        for first_a, last_a in left
        for first_b, last_b in right
    )


def _ranges_cover(
    covering: Iterable[tuple[int, int]],
    required: Iterable[tuple[int, int]],
) -> bool:
    normalized = sorted(covering)
    for required_first, required_last in required:
        cursor = required_first
        for first, last in normalized:
            if last < cursor:
                continue
            if first > cursor:
                break
            cursor = max(cursor, last + 1)
            if cursor > required_last:
                break
        if cursor <= required_last:
            return False
    return True


def _port_relation(
    expected: int | None,
    observed_ranges: tuple[Any, ...],
) -> str:
    """Compare the observed destination-port set with the policy port."""
    if expected is None:
        return "equal" if not observed_ranges else "observed_subset"

    observed = tuple((item.first, item.last) for item in observed_ranges)
    if not observed:
        return "observed_superset"

    required = ((expected, expected),)
    if not _ranges_overlap(observed, required):
        return "disjoint"

    observed_subset = all(
        first >= expected and last <= expected
        for first, last in observed
    )
    observed_superset = _ranges_cover(observed, required)

    if observed_subset and observed_superset:
        return "equal"
    if observed_subset:
        return "observed_subset"
    if observed_superset:
        return "observed_superset"
    return "partial"


def _scope_relation(policy_rule: dict[str, Any], observed: RuleIR) -> str:
    relations = (
        _protocol_relation(policy_rule["protocol"], observed.protocol),
        _network_relation(policy_rule.get("source", "any"), observed.source),
        _port_relation(
            policy_rule.get("destination_port"),
            observed.destination_ports,
        ),
    )
    if "disjoint" in relations:
        return "disjoint"
    if all(item == "equal" for item in relations):
        return "equal"
    if all(item in {"equal", "observed_subset"} for item in relations):
        return "observed_subset"
    if all(item in {"equal", "observed_superset"} for item in relations):
        return "observed_superset"
    return "partial"


def _unmodelled_selectors(rule: RuleIR) -> list[str]:
    """Selectors which cannot be represented by the present JSON policy schema."""
    selectors: list[str] = []
    if rule.destination is not None:
        selectors.append("destination")
    if rule.input_interface is not None:
        selectors.append("input_interface")
    if rule.output_interface is not None:
        selectors.append("output_interface")
    if rule.source_ports:
        selectors.append("source_ports")
    if rule.either_ports:
        selectors.append("either_ports")
    if rule.connection_states:
        selectors.append("connection_states")
    if rule.fragment_only is not None:
        selectors.append("fragment_only")
    if rule.tcp_syn_only is not None:
        selectors.append("tcp_syn_only")
    if rule.tcp_flags_mask is not None:
        selectors.append("tcp_flags")
    if rule.negated_conditions:
        selectors.append("negated_conditions")
    return selectors


def _impact(status: str, action: str) -> str:
    if status == "ACTION_MISMATCH":
        return (
            "potential_exposure"
            if action == "drop"
            else "availability_or_policy_violation"
        )
    if status == "MISSING":
        return (
            "potential_exposure"
            if action == "drop"
            else "required_allow_rule_missing"
        )
    if status == "BROADER_SCOPE":
        return (
            "potential_exposure"
            if action == "accept"
            else "broader_blocking_than_policy"
        )
    if status == "NARROWER_SCOPE":
        return (
            "coverage_gap"
            if action == "accept"
            else "potential_exposure"
        )
    if status == "PARTIAL_OVERLAP":
        return "scope_divergence"
    return "none"


def _comparison_record(
    *,
    rule_id: str,
    family: str,
    chain: str,
    status: str,
    expected_action: str,
    observed_action: str | None = None,
    observed_lines: list[int] | None = None,
    scope_relation: str | None = None,
    unmodelled_selectors: list[str] | None = None,
    reason: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "family": family,
        "chain": chain,
        "status": status,
        "expected_action": expected_action.upper(),
        "observed_action": observed_action,
        "observed_lines": observed_lines or [],
        "scope_relation": scope_relation,
        "impact": _impact(status, expected_action),
        "unmodelled_selectors": unmodelled_selectors or [],
        "reason": reason,
    }


def _compare_one_rule(
    policy_rule: dict[str, Any],
    family: str,
    rules: list[RuleIR] | None,
    parse_error: bool,
) -> dict[str, Any]:
    rule_id = policy_rule["id"]
    chain = policy_rule["chain"].upper()
    action = policy_rule["action"]

    source = policy_rule.get("source", "any")
    if source != "any":
        network = ipaddress.ip_network(source, strict=False)
        expected_version = 4 if family == "ipv4" else 6
        if network.version != expected_version:
            return _comparison_record(
                rule_id=rule_id,
                family=family,
                chain=chain,
                status="NOT_APPLICABLE",
                expected_action=action,
                reason="A rede de origem da política pertence à outra família IP.",
            )

    if parse_error or rules is None:
        return _comparison_record(
            rule_id=rule_id,
            family=family,
            chain=chain,
            status="INCONCLUSIVE",
            expected_action=action,
            reason="Não foi possível gerar uma IR fiável para o snapshot desta família.",
        )

    chain_rules = [
        rule for rule in rules
        if rule.table == "filter" and rule.chain == chain
    ]
    partial_rules = [
        rule for rule in chain_rules if rule.interpretation != "complete"
    ]
    chain_transfers = [
        rule for rule in chain_rules
        if rule.interpretation == "complete"
        and rule.target_operation in {"jump", "goto"}
        and (rule.target or "").upper() not in TERMINAL_VERDICTS
    ]
    candidates: list[tuple[RuleIR, str]] = []

    for observed in chain_rules:
        if (
            observed.interpretation != "complete"
            or observed.target_operation != "jump"
            or (observed.target or "").upper() not in TERMINAL_VERDICTS
        ):
            continue

        relation = _scope_relation(policy_rule, observed)
        if relation != "disjoint":
            candidates.append((observed, relation))

    if not candidates:
        if partial_rules or chain_transfers:
            uncertain_lines = sorted(
                rule.line_number for rule in (*partial_rules, *chain_transfers)
            )
            reason = (
                "Existem regras parcialmente interpretadas na cadeia; "
                "não é possível provar que a regra esperada esteja ausente."
                if partial_rules
                else
                "A cadeia transfere a avaliação para uma chain de utilizador; "
                "a comparação atual não segue esse fluxo e não pode provar ausência."
            )
            return _comparison_record(
                rule_id=rule_id,
                family=family,
                chain=chain,
                status="INCONCLUSIVE",
                expected_action=action,
                observed_lines=uncertain_lines,
                reason=reason,
            )
        return _comparison_record(
            rule_id=rule_id,
            family=family,
            chain=chain,
            status="MISSING",
            expected_action=action,
            reason=(
                "Não foi encontrada uma regra terminal totalmente interpretada "
                "com condições que se sobreponham à regra declarada na política."
            ),
        )

    if len(candidates) != 1:
        return _comparison_record(
            rule_id=rule_id,
            family=family,
            chain=chain,
            status="INCONCLUSIVE",
            expected_action=action,
            observed_action="multiple",
            observed_lines=sorted(rule.line_number for rule, _ in candidates),
            reason=(
                "Foram encontradas várias regras candidatas; a comparação "
                "não agrega conjuntos de regras nem avalia a ordem efetiva."
            ),
        )

    observed, relation = candidates[0]
    extra = _unmodelled_selectors(observed)
    observed_action = (observed.target or "").upper()

    if extra:
        return _comparison_record(
            rule_id=rule_id,
            family=family,
            chain=chain,
            status="INCONCLUSIVE",
            expected_action=action,
            observed_action=observed_action,
            observed_lines=[observed.line_number],
            scope_relation=relation,
            unmodelled_selectors=extra,
            reason=(
                "A regra observada contém condições que o esquema atual da "
                "política não representa; não é seguro afirmar equivalência."
            ),
        )

    if observed_action != action.upper():
        status = "ACTION_MISMATCH"
        reason = (
            "A regra observada tem uma decisão terminal diferente da decisão "
            "declarada na política."
        )
    elif relation == "equal":
        status = "MATCHED"
        reason = (
            "Cadeia, ação, protocolo, origem e porta de destino correspondem "
            "exatamente nos campos suportados."
        )
    elif relation == "observed_superset":
        status = "BROADER_SCOPE"
        reason = (
            "A regra observada abrange tráfego adicional face ao âmbito declarado "
            "na política."
        )
    elif relation == "observed_subset":
        status = "NARROWER_SCOPE"
        reason = (
            "A regra observada cobre apenas uma parte do âmbito declarado "
            "na política."
        )
    else:
        status = "PARTIAL_OVERLAP"
        reason = (
            "A regra observada e a regra declarada na política sobrepõem-se, "
            "mas nenhuma contém totalmente a outra."
        )

    return _comparison_record(
        rule_id=rule_id,
        family=family,
        chain=chain,
        status=status,
        expected_action=action,
        observed_action=observed_action,
        observed_lines=[observed.line_number],
        scope_relation=relation,
        reason=reason,
    )


def compare_policy_rules_to_snapshots(
    policy: dict[str, Any],
    snapshots: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    """Compare policy rules with IPv4/IPv6 snapshots without applying changes.

    The comparison is rule-level and selector-based. It does not model
    first-match order, aggregate multiple rules to cover one policy rule,
    user-chain control flow, or real packet reachability.
    """
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise ValueError("A política tem de conter uma lista 'rules'.")

    parsed_by_family: dict[str, list[RuleIR] | None] = {}
    errors_by_family: dict[str, bool] = {}
    for family, snapshot_text in snapshots:
        if family not in {"ipv4", "ipv6"}:
            raise ValueError("A família tem de ser ipv4 ou ipv6.")
        try:
            parsed_by_family[family] = parse_iptables_rules_ir(
                snapshot_text,
                family,
            )
            errors_by_family[family] = False
        except ValueError:
            parsed_by_family[family] = None
            errors_by_family[family] = True

    comparisons: list[dict[str, Any]] = []
    for family, _ in snapshots:
        for policy_rule in policy["rules"]:
            comparisons.append(
                _compare_one_rule(
                    policy_rule,
                    family,
                    parsed_by_family[family],
                    errors_by_family[family],
                )
            )

    counts = {
        status: sum(item["status"] == status for item in comparisons)
        for status in (
            "MATCHED",
            "MISSING",
            "ACTION_MISMATCH",
            "BROADER_SCOPE",
            "NARROWER_SCOPE",
            "PARTIAL_OVERLAP",
            "INCONCLUSIVE",
            "NOT_APPLICABLE",
        )
    }
    conclusive = sum(
        item["status"] in CONCLUSIVE_STATUSES for item in comparisons
    )
    drift_count = sum(
        counts[status]
        for status in (
            "MISSING",
            "ACTION_MISMATCH",
            "BROADER_SCOPE",
            "NARROWER_SCOPE",
            "PARTIAL_OVERLAP",
        )
    )

    findings = [
        item for item in comparisons
        if item["status"] not in {"MATCHED", "NOT_APPLICABLE"}
    ]

    return {
        "schema_version": "1.0",
        "comparison_model": "supported_policy_rule_selectors",
        "summary": {
            "policy_rules_total": len(policy["rules"]),
            "family_rule_comparisons": len(comparisons),
            "rules_semantically_compared": conclusive,
            "rules_matched": counts["MATCHED"],
            "rules_missing": counts["MISSING"],
            "rules_action_mismatches": counts["ACTION_MISMATCH"],
            "rules_broader_scope": counts["BROADER_SCOPE"],
            "rules_narrower_scope": counts["NARROWER_SCOPE"],
            "rules_partial_overlap": counts["PARTIAL_OVERLAP"],
            "rules_inconclusive": counts["INCONCLUSIVE"],
            "rules_not_applicable": counts["NOT_APPLICABLE"],
            "conclusive_rule_drifts": drift_count,
            "findings_total": len(findings),
        },
        "comparisons": comparisons,
        "findings": findings,
        "limitations": [
            "A comparação cobre apenas chain, action, protocol, source e destination_port.",
            "O campo service da política é tratado como rótulo descritivo; não é convertido em condições iptables.",
            "Condições observadas de destino, interfaces, portas de origem, estado de ligação, fragmentos ou flags TCP tornam a comparação inconclusiva.",
            "A comparação é por regra; não combina várias regras para satisfazer uma única regra da política.",
            "Não avalia ordem first-match, saltos para chains de utilizador, NAT, routing ou alcance real dos pacotes.",
            "Uma correspondência exata dos campos suportados não prova, por si só, conformidade integral da firewall.",
        ],
        "integrity_note": (
            "Não são copiados para o relatório os valores de endereços, redes ou portas "
            "das condições observadas; são publicados apenas IDs, cadeias, linhas e "
            "classificações."
        ),
    }
