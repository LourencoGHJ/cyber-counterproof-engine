"""Conservative comparison of declarative policy rules with iptables-save IR.

Only fields represented by the current policy schema are compared:
chain, action, protocol, source network, destination port, connection
states and exact input/output interfaces. Additional selectors in observed
rules are not silently ignored;
they make the result inconclusive when the policy cannot express them.
"""
from __future__ import annotations

import ipaddress
from types import SimpleNamespace
from typing import Any, Iterable

from cce.iptables_ir import RuleIR, parse_iptables_rules_ir
from cce.iptables_save import parse_iptables_save


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

def _connection_state_relation(
    policy_rule: dict[str, Any],
    observed: RuleIR,
) -> str:
    """Compare the allowed connection-state sets; an omitted policy field means any state."""
    expected_values = policy_rule.get("connection_states")
    expected = set(expected_values or [])
    actual = set(observed.connection_states)

    if not expected:
        return "equal" if not actual else "observed_subset"
    if not actual:
        return "observed_superset"
    if actual == expected:
        return "equal"
    if actual.issubset(expected):
        return "observed_subset"
    if expected.issubset(actual):
        return "observed_superset"
    if actual.isdisjoint(expected):
        return "disjoint"
    return "partial"


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


def _is_exact_interface_selector(value: str) -> bool:
    """Aceita apenas seletores de interface com nome exato."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= 15
        and value not in {".", ".."}
        and not any(
            character.isspace()
            or character in "/:"
            or ord(character) < 32
            for character in value
        )
        and not value.startswith("!")
        and not value.endswith("+")
    )


def _interface_relation(
    expected: str | None,
    observed: str | None,
) -> str:
    """Compara interfaces exatas; ausência significa qualquer interface."""
    if expected is not None and not _is_exact_interface_selector(expected):
        return "partial"
    if observed is not None and not _is_exact_interface_selector(observed):
        return "partial"

    if expected is None:
        return "equal" if observed is None else "observed_subset"
    if observed is None:
        return "observed_superset"

    return "equal" if expected == observed else "disjoint"


def _scope_relation(policy_rule: dict[str, Any], observed: RuleIR) -> str:
    relations = (
        _protocol_relation(policy_rule["protocol"], observed.protocol),
        _network_relation(policy_rule.get("source", "any"), observed.source),
        _port_relation(
            policy_rule.get("destination_port"),
            observed.destination_ports,
        ),
        _connection_state_relation(policy_rule, observed),
        _interface_relation(
            policy_rule.get("input_interface"),
            observed.input_interface,
        ),
        _interface_relation(
            policy_rule.get("output_interface"),
            observed.output_interface,
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
    if (
        rule.input_interface is not None
        and not _is_exact_interface_selector(rule.input_interface)
    ):
        selectors.append("input_interface_pattern")
    if (
        rule.output_interface is not None
        and not _is_exact_interface_selector(rule.output_interface)
    ):
        selectors.append("output_interface_pattern")
    if rule.source_ports:
        selectors.append("source_ports")
    if rule.either_ports:
        selectors.append("either_ports")
    if rule.fragment_only is not None:
        selectors.append("fragment_only")
    if rule.tcp_syn_only is not None:
        selectors.append("tcp_syn_only")
    if rule.tcp_flags_mask is not None:
        selectors.append("tcp_flags")
    if rule.negated_conditions:
        selectors.append("negated_conditions")
    return selectors


def _flow_unmodelled_features(path_rules: Iterable[RuleIR]) -> list[str]:
    """Return safe feature labels without exposing firewall rule values."""
    features: set[str] = set()

    for rule in path_rules:
        features.update(_unmodelled_selectors(rule))

        if rule.interpretation != "complete":
            features.add("partial_interpretation")
        if getattr(rule, "unsupported_modules", ()):
            features.add("unsupported_module")
        if getattr(rule, "unsupported_options", ()):
            features.add("unsupported_option")
        if getattr(rule, "unsupported_targets", ()):
            features.add("unsupported_target")

    return sorted(features)


def _impact(status: str, action: str) -> str:
    if status == "ACTION_MISMATCH":
        return (
            "potential_exposure"
            if action in {"drop", "reject"}
            else "availability_or_policy_violation"
        )
    if status == "MISSING":
        return (
            "potential_exposure"
            if action in {"drop", "reject"}
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
    flow_path: list[dict[str, Any]] | None = None,
    reason: str,
) -> dict[str, Any]:
    record = {
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
    if flow_path is not None:
        record["flow_path"] = flow_path
    return record




def _combined_scope_relation(
    policy_rule: dict[str, Any],
    path_rules: list[RuleIR],
) -> str:
    """Compare policy scope with the intersection of supported path selectors."""
    protocols = {
        rule.protocol
        for rule in path_rules
        if rule.protocol not in (None, "all")
    }
    if len(protocols) > 1:
        return "disjoint"

    source_network = None
    for rule in path_rules:
        if rule.source is None:
            continue

        candidate = ipaddress.ip_network(rule.source, strict=False)
        if source_network is None:
            source_network = candidate
        elif candidate.subnet_of(source_network):
            source_network = candidate
        elif not source_network.subnet_of(candidate):
            return "disjoint"

    port_ranges: list[tuple[int, int]] | None = None
    for rule in path_rules:
        current = [
            (item.first, item.last)
            for item in rule.destination_ports
        ]
        if not current:
            continue

        if port_ranges is None:
            port_ranges = current
            continue

        intersections = []
        for first_a, last_a in port_ranges:
            for first_b, last_b in current:
                first = max(first_a, first_b)
                last = min(last_a, last_b)
                if first <= last:
                    intersections.append((first, last))

        if not intersections:
            return "disjoint"

        port_ranges = intersections

    states: set[str] | None = None
    for rule in path_rules:
        current_states = set(rule.connection_states)
        if not current_states:
            continue

        states = (
            current_states
            if states is None
            else states.intersection(current_states)
        )
        if not states:
            return "disjoint"

    interfaces: dict[str, str | None] = {}

    for field in ("input_interface", "output_interface"):
        values: set[str] = set()

        for rule in path_rules:
            value = getattr(rule, field)
            if value is None:
                continue
            if not _is_exact_interface_selector(value):
                return "partial"
            values.add(value)

        if len(values) > 1:
            return "disjoint"

        interfaces[field] = next(iter(values), None)

    observed = SimpleNamespace(
        protocol=next(iter(protocols), None),
        source=(
            source_network.with_prefixlen
            if source_network is not None
            else None
        ),
        destination_ports=tuple(
            SimpleNamespace(first=first, last=last)
            for first, last in (port_ranges or [])
        ),
        connection_states=tuple(sorted(states or ())),
        input_interface=interfaces["input_interface"],
        output_interface=interfaces["output_interface"],
    )
    return _scope_relation(policy_rule, observed)


def _analyze_policy_chain_flow(
    policy_rule: dict[str, Any],
    rules: list[RuleIR],
    declared_filter_chains: set[str],
) -> dict[str, Any]:
    """Follow only paths that cover the complete supported policy scope.

    Partial branches, negations, unsupported selectors and recursion remain
    inconclusive. No packet samples are used to claim semantic equivalence.
    """
    root = policy_rule["chain"].upper()
    if root not in declared_filter_chains:
        return {
            "kind": "inconclusive",
            "flow_path": [],
            "observed_lines": [],
            "reason": "A chain base da política não existe no snapshot.",
        }

    rules_by_chain: dict[str, list[RuleIR]] = {
        chain: [] for chain in declared_filter_chains
    }
    for rule in rules:
        if rule.table == "filter" and rule.chain in rules_by_chain:
            rules_by_chain[rule.chain].append(rule)

    active_chains: set[str] = set()
    steps = 0
    max_depth = 32
    max_steps = 4096

    def make_result(
        kind: str,
        path_rules: list[RuleIR],
        flow_path: list[dict[str, Any]],
        **extra: Any,
    ) -> dict[str, Any]:
        return {
            "kind": kind,
            "path_rules": path_rules,
            "flow_path": flow_path,
            "observed_lines": sorted({
                item["line_number"] for item in flow_path
            }),
            **extra,
        }

    def walk(
        chain_name: str,
        path_rules: list[RuleIR],
        flow_path: list[dict[str, Any]],
        depth: int,
    ) -> dict[str, Any]:
        nonlocal steps

        if depth > max_depth:
            return make_result(
                "inconclusive",
                path_rules,
                flow_path,
                reason="O limite de profundidade entre chains foi excedido.",
            )

        if chain_name in active_chains:
            return make_result(
                "inconclusive",
                path_rules,
                flow_path,
                reason="Foi detetada recursão no caminho de chains.",
            )

        if chain_name not in rules_by_chain:
            return make_result(
                "inconclusive",
                path_rules,
                flow_path,
                reason="O caminho referencia uma chain não resolvida.",
            )

        active_chains.add(chain_name)
        current_rules = list(path_rules)
        current_path = list(flow_path)

        try:
            for observed in rules_by_chain[chain_name]:
                steps += 1
                entry = {
                    "chain": chain_name,
                    "line_number": observed.line_number,
                    "operation": observed.target_operation,
                    "target": observed.target,
                }

                if steps > max_steps:
                    return make_result(
                        "inconclusive",
                        current_rules,
                        current_path + [entry],
                        reason="O limite de regras analisadas foi excedido.",
                    )

                if observed.negated_conditions:
                    return make_result(
                        "inconclusive",
                        current_rules,
                        current_path + [entry],
                        reason=(
                            "Uma condição negada impede provar a cobertura "
                            "integral do âmbito da política."
                        ),
                    )

                trial_rules = current_rules + [observed]
                relation = _combined_scope_relation(
                    policy_rule,
                    trial_rules,
                )

                if relation == "disjoint":
                    continue

                candidate_path = current_path + [{
                    **entry,
                    "scope_relation": relation,
                }]

                if relation not in {"equal", "observed_superset"}:
                    return make_result(
                        "inconclusive",
                        trial_rules,
                        candidate_path,
                        reason=(
                            "Uma regra cobre apenas parte do âmbito da política; "
                            "a análise não agrega ainda ramos parciais."
                        ),
                    )

                if (
                    observed.interpretation != "complete"
                    or _unmodelled_selectors(observed)
                ):
                    return make_result(
                        "inconclusive",
                        trial_rules,
                        candidate_path,
                        reason=(
                            "Uma regra alcançável contém semântica não suportada "
                            "pela comparação atual."
                        ),
                    )

                current_rules = trial_rules
                current_path = candidate_path
                target = observed.target or ""
                target_verdict = target.upper()

                if target_verdict in TERMINAL_VERDICTS:
                    return make_result(
                        "terminal",
                        current_rules,
                        current_path,
                        action=target_verdict,
                        scope_relation=relation,
                    )

                if target_verdict == "RETURN":
                    return make_result(
                        "return",
                        current_rules,
                        current_path,
                    )

                if (
                    observed.target_operation not in {"jump", "goto"}
                    or target not in declared_filter_chains
                ):
                    return make_result(
                        "inconclusive",
                        current_rules,
                        current_path,
                        reason="O target não tem fluxo suportado.",
                    )

                child = walk(
                    target,
                    current_rules,
                    current_path,
                    depth + 1,
                )

                if child["kind"] in {"terminal", "inconclusive"}:
                    return child

                current_rules = child["path_rules"]
                current_path = child["flow_path"]

                if observed.target_operation == "jump":
                    continue

                # GOTO propagates the child's RETURN to this chain's caller.
                return make_result(
                    "return",
                    current_rules,
                    current_path,
                )

            # End of a user chain has implicit RETURN semantics.
            return make_result(
                "return",
                current_rules,
                current_path,
            )
        finally:
            active_chains.remove(chain_name)

    result = walk(root, [], [], 1)
    if result["kind"] == "return":
        result["reason"] = (
            "O fluxo regressa à chain chamadora ou termina na chain base "
            "sem demonstrar uma decisão terminal para todo o âmbito."
        )
    return result


def _compare_one_rule(
    policy_rule: dict[str, Any],
    family: str,
    rules: list[RuleIR] | None,
    declared_filter_chains: set[str],
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
        and rule.target in declared_filter_chains
        and (rule.target or "").upper() not in TERMINAL_VERDICTS
    ]

    if chain_transfers:
        flow = _analyze_policy_chain_flow(
            policy_rule,
            rules,
            declared_filter_chains,
        )
        flow_path = flow["flow_path"]
        observed_lines = flow["observed_lines"]

        if flow["kind"] == "terminal":
            observed_action = flow["action"]
            relation = flow["scope_relation"]

            if observed_action != action.upper():
                status = "ACTION_MISMATCH"
                reason = (
                    "O fluxo entre chains termina numa decisão diferente "
                    "da ação declarada na política."
                )
            elif relation == "equal":
                status = "MATCHED"
                reason = (
                    "O fluxo entre chains cobre exatamente o âmbito da política "
                    "e termina na ação esperada."
                )
            else:
                status = "BROADER_SCOPE"
                reason = (
                    "O fluxo entre chains termina na ação esperada, mas a "
                    "interseção dos seletores cobre um âmbito mais amplo."
                )

            return _comparison_record(
                rule_id=rule_id,
                family=family,
                chain=chain,
                status=status,
                expected_action=action,
                observed_action=observed_action,
                observed_lines=observed_lines,
                scope_relation=relation,
                flow_path=flow_path,
                reason=reason,
            )

        if flow["kind"] == "return" and not flow_path:
            return _comparison_record(
                rule_id=rule_id,
                family=family,
                chain=chain,
                status="MISSING",
                expected_action=action,
                reason=(
                    "Não foi encontrado um caminho de chain que corresponda "
                    "ao âmbito da política nem uma regra terminal correspondente."
                ),
            )

        return _comparison_record(
            rule_id=rule_id,
            family=family,
            chain=chain,
            status="INCONCLUSIVE",
            expected_action=action,
            observed_lines=observed_lines,
            unmodelled_selectors=_flow_unmodelled_features(
                flow.get("path_rules", [])
            ),
            flow_path=flow_path,
            reason=flow.get(
                "reason",
                "Não foi possível provar o resultado do fluxo entre chains.",
            ),
        )

    candidates: list[tuple[RuleIR, str]] = []

    for observed in chain_rules:
        if (
            observed.interpretation != "complete"
            or observed.target_operation != "jump"
            or (observed.target or "").upper() not in TERMINAL_VERDICTS
        ):
            continue

        relation = _scope_relation(policy_rule, observed)
        if relation != "disjoint" or observed.negated_conditions:
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
            "Cadeia, ação, protocolo, origem, porta de destino, estados de "
            "ligação e interfaces correspondem exatamente nos campos suportados."
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

    The comparison is rule-level and selector-based, including supported
    connection-state sets. It does not model
    first-match order, aggregate multiple rules to cover one policy rule,
    user-chain control flow, or real packet reachability.
    """
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise ValueError("A política tem de conter uma lista 'rules'.")

    parsed_by_family: dict[str, list[RuleIR] | None] = {}
    filter_chains_by_family: dict[str, set[str]] = {}
    errors_by_family: dict[str, bool] = {}
    for family, snapshot_text in snapshots:
        if family not in {"ipv4", "ipv6"}:
            raise ValueError("A família tem de ser ipv4 ou ipv6.")
        try:
            structural = parse_iptables_save(snapshot_text, family)
            if structural["summary"]["malformed_lines"] > 0:
                raise ValueError(
                    "O snapshot contém linhas estruturalmente malformadas."
                )
            parsed_by_family[family] = parse_iptables_rules_ir(
                snapshot_text,
                family,
            )
            filter_chains_by_family[family] = {
                chain["name"]
                for chain in structural["chains"]
                if chain["table"] == "filter"
            }
            errors_by_family[family] = False
        except ValueError:
            parsed_by_family[family] = None
            filter_chains_by_family[family] = set()
            errors_by_family[family] = True

    comparisons: list[dict[str, Any]] = []
    for family, _ in snapshots:
        for policy_rule in policy["rules"]:
            comparisons.append(
                _compare_one_rule(
                    policy_rule,
                    family,
                    parsed_by_family[family],
                    filter_chains_by_family[family],
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
