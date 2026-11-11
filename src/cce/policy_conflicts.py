"""Conservative static detection of iptables rule redundancy and verdict conflicts."""

from __future__ import annotations

import ipaddress
from itertools import product
from typing import Any

from cce.iptables_ir import RuleIR, TCP_FLAG_ORDER, parse_iptables_rules_ir


TERMINAL_VERDICTS = {"ACCEPT", "DROP", "REJECT"}
RANGE_FIELDS = ("source_ports", "destination_ports", "either_ports")
NETWORK_FIELDS = ("source", "destination")
INTERFACE_FIELDS = ("input_interface", "output_interface")


def _terminal_verdict(rule: RuleIR) -> str | None:
    if rule.target_operation != "jump" or rule.target is None:
        return None
    target = rule.target.upper()
    return target if target in TERMINAL_VERDICTS else None


def _rule_signature(rule: RuleIR) -> tuple[Any, ...]:
    """Canonicalize only packet-matching conditions, excluding order and target."""
    return (
        rule.family,
        rule.table,
        rule.chain,
        None if rule.protocol in (None, "all") else rule.protocol,
        rule.source,
        rule.destination,
        rule.input_interface,
        rule.output_interface,
        tuple(sorted((p.first, p.last) for p in rule.source_ports)),
        tuple(sorted((p.first, p.last) for p in rule.destination_ports)),
        tuple(sorted((p.first, p.last) for p in rule.either_ports)),
        tuple(sorted(rule.connection_states)),
        rule.fragment_only,
        rule.tcp_syn_only,
        rule.tcp_flags_mask,
        rule.tcp_flags_comp,
        tuple(sorted(rule.negated_conditions)),
    )


def _ranges_overlap(left: tuple[Any, ...], right: tuple[Any, ...]) -> bool:
    return any(
        a.first <= b.last and b.first <= a.last
        for a in left
        for b in right
    )


def _ranges_cover(covering: tuple[Any, ...], covered: tuple[Any, ...]) -> bool:
    """Return true only when the covering interval union contains every range."""
    normalized = sorted((item.first, item.last) for item in covering)
    for required in covered:
        cursor = required.first
        for first, last in normalized:
            if last < cursor:
                continue
            if first > cursor:
                break
            cursor = max(cursor, last + 1)
            if cursor > required.last:
                break
        if cursor <= required.last:
            return False
    return True


def _interface_scope(pattern: str) -> tuple[str, str]:
    if pattern.endswith("+"):
        return "prefix", pattern[:-1]
    return "exact", pattern


def _interfaces_overlap(left: str, right: str) -> bool:
    left_kind, left_value = _interface_scope(left)
    right_kind, right_value = _interface_scope(right)
    if left_kind == "exact" and right_kind == "exact":
        return left_value == right_value
    if left_kind == "exact":
        return left_value.startswith(right_value)
    if right_kind == "exact":
        return right_value.startswith(left_value)
    return left_value.startswith(right_value) or right_value.startswith(left_value)


def _interface_covers(covering: str, covered: str) -> bool:
    covering_kind, covering_value = _interface_scope(covering)
    covered_kind, covered_value = _interface_scope(covered)
    if covering_kind == "exact":
        return covered_kind == "exact" and covering_value == covered_value
    return covered_value.startswith(covering_value)


def _effective_boolean(rule: RuleIR, field: str) -> bool | None:
    # The IR stores the effective value for fragment_only and tcp_syn_only;
    # negated_conditions is retained as metadata and must not invert it again.
    return getattr(rule, field)


def _matches_tcp_flags(rule: RuleIR, flags: frozenset[str]) -> bool:
    if rule.tcp_syn_only is not None:
        syn_match = (
            "SYN" in flags
            and not flags.intersection({"ACK", "RST", "FIN"})
        )
        if not rule.tcp_syn_only:
            syn_match = not syn_match
        if not syn_match:
            return False

    if rule.tcp_flags_mask is not None:
        selected = flags.intersection(rule.tcp_flags_mask)
        matches = selected == set(rule.tcp_flags_comp or ())
        if "tcp_flags" in rule.negated_conditions:
            matches = not matches
        if not matches:
            return False

    return True


_FLAG_COMBINATIONS = tuple(
    frozenset(flag for flag, enabled in zip(TCP_FLAG_ORDER, values) if enabled)
    for values in product((False, True), repeat=len(TCP_FLAG_ORDER))
)


def _has_tcp_flag_conditions(rule: RuleIR) -> bool:
    return rule.tcp_syn_only is not None or rule.tcp_flags_mask is not None


def _tcp_flag_sets_overlap(left: RuleIR, right: RuleIR) -> bool:
    if not (_has_tcp_flag_conditions(left) or _has_tcp_flag_conditions(right)):
        return True
    return any(
        _matches_tcp_flags(left, flags) and _matches_tcp_flags(right, flags)
        for flags in _FLAG_COMBINATIONS
    )


def _tcp_flags_cover(covering: RuleIR, covered: RuleIR) -> bool:
    if not _has_tcp_flag_conditions(covering):
        return True
    return all(
        not _matches_tcp_flags(covered, flags)
        or _matches_tcp_flags(covering, flags)
        for flags in _FLAG_COMBINATIONS
    )


def _rule_has_no_tcp_flag_match(rule: RuleIR) -> bool:
    """Prove that the supported TCP-flag predicates have no satisfying flags."""
    if not _has_tcp_flag_conditions(rule):
        return False
    return not any(
        _matches_tcp_flags(rule, flags)
        for flags in _FLAG_COMBINATIONS
    )


def _rules_are_disjoint(left: RuleIR, right: RuleIR) -> bool:
    """Prove disjointness from one independent, fully understood selector."""
    if left.family != right.family:
        return True

    if (
        left.protocol not in (None, "all")
        and right.protocol not in (None, "all")
        and "protocol" not in left.negated_conditions
        and "protocol" not in right.negated_conditions
        and left.protocol != right.protocol
    ):
        return True

    for field in NETWORK_FIELDS:
        left_network = getattr(left, field)
        right_network = getattr(right, field)
        if (
            left_network is not None
            and right_network is not None
            and field not in left.negated_conditions
            and field not in right.negated_conditions
        ):
            if not ipaddress.ip_network(left_network).overlaps(
                ipaddress.ip_network(right_network)
            ):
                return True

    for field in INTERFACE_FIELDS:
        left_interface = getattr(left, field)
        right_interface = getattr(right, field)
        if (
            left_interface is not None
            and right_interface is not None
            and field not in left.negated_conditions
            and field not in right.negated_conditions
            and not _interfaces_overlap(left_interface, right_interface)
        ):
            return True

    for field in RANGE_FIELDS:
        left_ranges = getattr(left, field)
        right_ranges = getattr(right, field)
        if (
            left_ranges
            and right_ranges
            and field not in left.negated_conditions
            and field not in right.negated_conditions
            and not _ranges_overlap(left_ranges, right_ranges)
        ):
            return True

    if (
        left.connection_states
        and right.connection_states
        and "connection_states" not in left.negated_conditions
        and "connection_states" not in right.negated_conditions
        and not set(left.connection_states).intersection(right.connection_states)
    ):
        return True

    for field in ("fragment_only", "tcp_syn_only"):
        left_value = _effective_boolean(left, field)
        right_value = _effective_boolean(right, field)
        if (
            left_value is not None
            and right_value is not None
            and left_value != right_value
        ):
            return True

    if not _tcp_flag_sets_overlap(left, right):
        return True

    return False


def _rule_covers(covering: RuleIR, covered: RuleIR) -> bool:
    """Prove that every packet matching 'covered' also matches 'covering'."""
    if (
        covering.family != covered.family
        or covering.table != covered.table
        or covering.chain != covered.chain
        or covering.interpretation != "complete"
        or covered.interpretation != "complete"
        or covering.negated_conditions
        or covered.negated_conditions
    ):
        return False

    if covering.protocol not in (None, "all"):
        if covered.protocol != covering.protocol:
            return False

    for field in NETWORK_FIELDS:
        outer = getattr(covering, field)
        inner = getattr(covered, field)
        if outer is not None:
            if inner is None:
                return False
            if not ipaddress.ip_network(inner).subnet_of(
                ipaddress.ip_network(outer)
            ):
                return False

    for field in INTERFACE_FIELDS:
        outer = getattr(covering, field)
        inner = getattr(covered, field)
        if outer is not None:
            if inner is None or not _interface_covers(outer, inner):
                return False

    for field in RANGE_FIELDS:
        outer = getattr(covering, field)
        inner = getattr(covered, field)
        if outer and (not inner or not _ranges_cover(outer, inner)):
            return False

    if covering.connection_states:
        if not covered.connection_states:
            return False
        if not set(covered.connection_states).issubset(
            covering.connection_states
        ):
            return False

    outer_fragment = covering.fragment_only
    inner_fragment = covered.fragment_only
    if outer_fragment is not None and inner_fragment != outer_fragment:
        return False

    if not _tcp_flags_cover(covering, covered):
        return False

    return True


def _finding(
    code: str,
    severity: str,
    chain: str,
    earlier: RuleIR,
    later: RuleIR,
    earlier_verdict: str,
    later_verdict: str,
    certainty: str,
    title: str,
    description: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "certainty": certainty,
        "table": earlier.table,
        "chain": chain,
        "earlier_line": earlier.line_number,
        "later_line": later.line_number,
        "earlier_verdict": earlier_verdict,
        "later_verdict": later_verdict,
        "title": title,
        "description": description,
    }


def analyze_iptables_rule_conflicts(
    snapshot_text: str,
    family: str,
) -> dict[str, Any]:
    """Analyze ordered, fully interpreted terminal rules in the filter table.

    The analysis is conservative: it proves full shadowing only when an
    earlier terminal rule covers the complete match set of a later rule.
    Otherwise, cross-verdict overlap is reported as potential.
    """
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("family tem de ser 'ipv4' ou 'ipv6'.")

    all_rules = parse_iptables_rules_ir(snapshot_text, family)
    filter_rules = [rule for rule in all_rules if rule.table == "filter"]
    partial_rules = [
        rule for rule in filter_rules if rule.interpretation != "complete"
    ]

    complete_terminal_rules = [
        rule
        for rule in filter_rules
        if rule.interpretation == "complete"
        and _terminal_verdict(rule) is not None
    ]
    unmatchable_rules = [
        rule
        for rule in complete_terminal_rules
        if _rule_has_no_tcp_flag_match(rule)
    ]
    terminal_rules = [
        rule
        for rule in complete_terminal_rules
        if rule not in unmatchable_rules
    ]
    by_chain: dict[str, list[RuleIR]] = {}
    for rule in terminal_rules:
        by_chain.setdefault(rule.chain, []).append(rule)

    findings: list[dict[str, Any]] = []
    for rule in unmatchable_rules:
        verdict = _terminal_verdict(rule)
        findings.append(
            {
                "code": "UNMATCHABLE_RULE",
                "severity": "high",
                "certainty": "proven",
                "table": rule.table,
                "chain": rule.chain,
                "earlier_line": None,
                "later_line": rule.line_number,
                "earlier_verdict": None,
                "later_verdict": verdict,
                "title": "Regra sem qualquer correspondência possível",
                "description": (
                    "As condições de flags TCP desta regra são contraditórias "
                    "ou impossíveis de satisfazer. Nenhum conjunto de flags "
                    "avaliado pode corresponder à regra."
                ),
            }
        )

    duplicate_count = 0
    unmatchable_count = len(unmatchable_rules)
    redundant_count = 0
    shadowed_count = 0
    overlap_count = 0

    for chain, chain_rules in by_chain.items():
        chain_rules.sort(key=lambda item: item.line_number)
        shadowed_lines: set[int] = set()

        for later_index, later in enumerate(chain_rules):
            later_verdict = _terminal_verdict(later)
            assert later_verdict is not None
            potential_pairs: list[tuple[RuleIR, str]] = []
            shadowing: tuple[RuleIR, str, str] | None = None

            for earlier in chain_rules[:later_index]:
                if earlier.line_number in shadowed_lines:
                    continue

                earlier_verdict = _terminal_verdict(earlier)
                assert earlier_verdict is not None

                same_match = _rule_signature(earlier) == _rule_signature(later)
                covers = same_match or _rule_covers(earlier, later)
                if covers:
                    shadowing = (earlier, earlier_verdict, "same" if same_match else "covered")
                    break

                if (
                    earlier_verdict != later_verdict
                    and not _rules_are_disjoint(earlier, later)
                ):
                    potential_pairs.append((earlier, earlier_verdict))

            if shadowing is not None:
                shadowed_lines.add(later.line_number)
                earlier, earlier_verdict, relation = shadowing
                if relation == "same" and earlier_verdict == later_verdict:
                    code = "DUPLICATE_RULE"
                    severity = "medium"
                    certainty = "proven"
                    title = "Regra duplicada"
                    description = (
                        "Esta regra repete as mesmas condições e a mesma decisão "
                        "de uma regra terminal anterior da mesma cadeia."
                    )
                    duplicate_count += 1
                elif earlier_verdict == later_verdict:
                    code = "REDUNDANT_RULE"
                    severity = "medium"
                    certainty = "proven"
                    title = "Regra redundante"
                    description = (
                        "Uma regra terminal anterior com a mesma decisão cobre "
                        "todos os pacotes que esta regra poderia corresponder."
                    )
                    redundant_count += 1
                else:
                    code = "SHADOWED_RULE"
                    severity = "high"
                    certainty = "proven"
                    title = "Regra inalcançável por sombreamento"
                    description = (
                        "Uma regra terminal anterior cobre todas as condições "
                        "desta regra e aplica uma decisão diferente. Esta regra "
                        "não será alcançada para os pacotes que a poderiam corresponder."
                    )
                    shadowed_count += 1

                findings.append(
                    _finding(
                        code,
                        severity,
                        chain,
                        earlier,
                        later,
                        earlier_verdict,
                        later_verdict,
                        certainty,
                        title,
                        description,
                    )
                )
                continue

            for earlier, earlier_verdict in potential_pairs:
                findings.append(
                    _finding(
                        "OVERLAPPING_VERDICTS",
                        "medium",
                        chain,
                        earlier,
                        later,
                        earlier_verdict,
                        later_verdict,
                        "potential",
                        "Regras com decisões potencialmente sobrepostas",
                        (
                            "As condições destas regras podem corresponder a "
                            "algum tráfego comum, mas não foi provado que a regra "
                            "anterior cubra integralmente a posterior. A ordem "
                            "das regras determina a decisão para a parte sobreposta."
                        ),
                    )
                )
                overlap_count += 1

    findings.sort(
        key=lambda item: (
            item["chain"],
            item["later_line"],
            item["earlier_line"] or 0,
            item["code"],
        )
    )
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"RC{index:04d}"

    return {
        "schema_version": "1.0",
        "family": family,
        "table": "filter",
        "summary": {
            "rules_total": len(all_rules),
            "filter_rules_total": len(filter_rules),
            "terminal_rules_analyzed": len(terminal_rules),
            "unmatchable_terminal_rules": unmatchable_count,
            "partial_rules_skipped": len(partial_rules),
            "non_terminal_rules_skipped": (
                len(filter_rules)
                - len(partial_rules)
                - len(complete_terminal_rules)
            ),
            "duplicate_rules": duplicate_count,
            "redundant_rules": redundant_count,
            "shadowed_rules": shadowed_count,
            "potential_verdict_overlaps": overlap_count,
            "findings_total": len(findings),
        },
        "findings": findings,
        "limitations": [
            "A análise compara apenas regras terminais totalmente interpretadas na mesma cadeia da tabela filter.",
            "A análise não prova se uma cadeia de utilizador é alcançável a partir de um hook.",
            "Regras parciais ou com semântica não suportada são excluídas das conclusões e contabilizadas separadamente.",
            "Sobreposições sem prova de sombreamento são assinaladas como potenciais, não como conflitos certos.",
            "Não são simulados NAT, routing, módulos stateful externos, nem alterações dinâmicas do ruleset.",
            "Nenhuma regra é aplicada, removida ou modificada.",
        ],
    }
