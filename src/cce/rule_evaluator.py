"""Conservative sequential evaluator for a supported iptables filter subset."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Any

from cce.iptables_ir import RuleIR, parse_iptables_rules_ir
from cce.iptables_save import parse_iptables_save
from cce.packet import Packet


TERMINAL_VERDICTS = {"ACCEPT", "DROP", "REJECT"}
SUPPORTED_HOOKS = {"INPUT", "OUTPUT", "FORWARD"}
DEFAULT_MAX_CHAIN_DEPTH = 32
DEFAULT_MAX_STEPS = 1024


@dataclass(frozen=True, slots=True)
class TraceStep:
    """One evaluated rule, without packet addresses or original rule text."""

    chain: str
    line_number: int
    result: str
    reason: str
    action: str | None = None


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Result of evaluating one packet at one filter hook."""

    status: str
    decision_source: str
    reason: str
    family: str
    table: str
    hook: str
    steps_evaluated: int
    trace: tuple[TraceStep, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result without packet identifiers."""
        result = asdict(self)
        result["trace"] = [asdict(step) for step in self.trace]
        result["limitations"] = list(self.limitations)
        return result


def _interface_matches(pattern: str, actual: str) -> bool:
    """Match exact interface names or iptables trailing-plus prefixes."""
    if pattern.endswith("+"):
        return actual.startswith(pattern[:-1])
    return actual == pattern


def _port_in_ranges(
    port: int,
    ranges: tuple[Any, ...],
) -> bool:
    return any(item.first <= port <= item.last for item in ranges)


def _match_rule(rule: RuleIR, packet: Packet) -> tuple[str, str]:
    """Return MATCH, NO_MATCH or UNKNOWN for a normalized rule."""
    if rule.family != packet.family:
        return "NO_MATCH", "address_family_mismatch"

    unknown_reasons: list[str] = []

    def check(value: bool | None, label: str) -> bool:
        if value is False:
            return False
        if value is None:
            if label not in unknown_reasons:
                unknown_reasons.append(label)
        return True

    if rule.protocol not in (None, "all"):
        matched = packet.protocol == rule.protocol
        if "protocol" in rule.negated_conditions:
            matched = not matched
        if not check(matched, "protocol_unavailable"):
            return "NO_MATCH", "protocol_mismatch"

    for field_name, network_text in (
        ("source", rule.source),
        ("destination", rule.destination),
    ):
        warning = f"unparsed_network:{field_name}"
        if network_text is None:
            if warning in rule.warnings:
                if not check(None, warning):
                    return "NO_MATCH", "network_unavailable"
            continue

        try:
            network = ipaddress.ip_network(network_text, strict=False)
            address_text = (
                packet.source_ip
                if field_name == "source"
                else packet.destination_ip
            )
            address = ipaddress.ip_address(address_text)
            matched = address in network
        except ValueError:
            matched = None

        if field_name in rule.negated_conditions and matched is not None:
            matched = not matched

        if not check(matched, f"{field_name}_match_unavailable"):
            return "NO_MATCH", f"{field_name}_mismatch"

    for field_name, pattern, actual in (
        ("input_interface", rule.input_interface, packet.input_interface),
        ("output_interface", rule.output_interface, packet.output_interface),
    ):
        if pattern is None:
            continue
        matched = (
            None
            if actual is None
            else _interface_matches(pattern, actual)
        )
        if field_name in rule.negated_conditions and matched is not None:
            matched = not matched
        if not check(matched, f"{field_name}_unavailable"):
            return "NO_MATCH", f"{field_name}_mismatch"

    for field_name, port, ranges in (
        ("source_ports", packet.source_port, rule.source_ports),
        ("destination_ports", packet.destination_port, rule.destination_ports),
    ):
        if not ranges:
            continue

        matched = None if port is None else _port_in_ranges(port, ranges)
        if field_name in rule.negated_conditions and matched is not None:
            matched = not matched

        if not check(matched, f"{field_name}_unavailable"):
            return "NO_MATCH", f"{field_name}_mismatch"

    if rule.either_ports:
        if packet.source_port is None and packet.destination_port is None:
            either_match: bool | None = None
        else:
            source_match = (
                None
                if packet.source_port is None
                else _port_in_ranges(packet.source_port, rule.either_ports)
            )
            destination_match = (
                None
                if packet.destination_port is None
                else _port_in_ranges(packet.destination_port, rule.either_ports)
            )
            if source_match is True or destination_match is True:
                either_match = True
            elif source_match is None or destination_match is None:
                either_match = None
            else:
                either_match = False

        if "either_ports" in rule.negated_conditions and either_match is not None:
            either_match = not either_match

        if not check(either_match, "either_ports_unavailable"):
            return "NO_MATCH", "either_ports_mismatch"

    if rule.connection_states:
        matched = (
            None
            if packet.connection_state is None
            else packet.connection_state in rule.connection_states
        )
        if "connection_states" in rule.negated_conditions and matched is not None:
            matched = not matched
        if not check(matched, "connection_state_unavailable"):
            return "NO_MATCH", "connection_state_mismatch"

    if rule.fragment_only is not None:
        matched = (
            None
            if packet.is_non_initial_fragment is None
            else packet.is_non_initial_fragment == rule.fragment_only
        )
        if not check(matched, "fragment_metadata_unavailable"):
            return "NO_MATCH", "fragment_mismatch"

    if rule.tcp_syn_only is not None:
        if packet.protocol != "tcp" or packet.tcp_flags is None:
            syn_match = None
        else:
            syn_match = (
                "SYN" in packet.tcp_flags
                and not packet.tcp_flags.intersection({"ACK", "RST", "FIN"})
            )
            if not rule.tcp_syn_only:
                syn_match = not syn_match

        if not check(syn_match, "tcp_flags_unavailable"):
            return "NO_MATCH", "tcp_flags_mismatch"

    if rule.tcp_flags_mask is not None:
        if packet.protocol != "tcp":
            # A TCP-flags selector on a non-TCP rule is structurally partial;
            # do not turn that ambiguity into a definitive non-match.
            flags_match: bool | None = None
        elif not rule.tcp_flags_mask:
            # NONE as a mask examines no bits; the empty comparison is true.
            flags_match = not rule.tcp_flags_comp
        elif packet.tcp_flags is None:
            flags_match = None
        else:
            selected_flags = packet.tcp_flags.intersection(
                rule.tcp_flags_mask
            )
            flags_match = selected_flags == set(rule.tcp_flags_comp or ())

        if "tcp_flags" in rule.negated_conditions and flags_match is not None:
            flags_match = not flags_match

        if not check(flags_match, "tcp_flags_unavailable"):
            return "NO_MATCH", "tcp_flags_mask_mismatch"

    # A known positive-condition mismatch safely rules the rule out even
    # when another condition is unsupported. If all known conditions match,
    # unsupported semantics prevent a definitive match.
    if rule.interpretation != "complete":
        return "UNKNOWN", "rule_contains_unsupported_or_ambiguous_conditions"

    if unknown_reasons:
        return "UNKNOWN", ",".join(unknown_reasons)

    return "MATCH", "all_supported_conditions_match"


def evaluate_iptables_packet(
    snapshot_text: str,
    family: str,
    packet: Packet,
    hook: str = "INPUT",
    table: str = "filter",
    max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> EvaluationResult:
    """Evaluate a packet against a snapshot using a conservative subset.

    The packet tuple represents the packet at the selected filter hook.
    Only filter-table INPUT, OUTPUT and FORWARD base chains are supported.
    No firewall command is executed and no rules are changed.
    """
    normalized_hook = hook.upper()
    if table != "filter":
        raise ValueError("A primeira versão só suporta a tabela filter.")
    if normalized_hook not in SUPPORTED_HOOKS:
        raise ValueError("hook tem de ser INPUT, OUTPUT ou FORWARD.")
    if not isinstance(packet, Packet):
        raise TypeError("packet tem de ser uma instância Packet.")
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("family tem de ser 'ipv4' ou 'ipv6'.")
    if max_chain_depth < 1 or max_steps < 1:
        raise ValueError("Os limites de execução têm de ser positivos.")

    limitations = (
        "A avaliação cobre apenas a tabela filter e os hooks INPUT, OUTPUT e FORWARD.",
        "O pacote representa o tuple observado no hook; NAT e encaminhamento anteriores não são simulados.",
        "Módulos, opções e targets não suportados produzem INCONCLUSIVE quando podem afetar a decisão.",
        "Políticas e regras são avaliadas na ordem do snapshot; não é feita qualquer alteração à firewall.",
        "O resultado é uma simulação do subconjunto implementado, não uma prova da decisão do kernel.",
    )

    def result(
        status: str,
        source: str,
        reason: str,
        trace: list[TraceStep],
    ) -> EvaluationResult:
        return EvaluationResult(
            status=status,
            decision_source=source,
            reason=reason,
            family=family,
            table=table,
            hook=normalized_hook,
            steps_evaluated=len(trace),
            trace=tuple(trace),
            limitations=limitations,
        )

    if packet.family != family:
        return result(
            "INCONCLUSIVE",
            "input_validation",
            "packet_family_does_not_match_snapshot_family",
            [],
        )

    try:
        structural = parse_iptables_save(snapshot_text, family)
        rules = parse_iptables_rules_ir(snapshot_text, family)
    except ValueError:
        return result(
            "INCONCLUSIVE",
            "snapshot_validation",
            "snapshot_could_not_be_interpreted_safely",
            [],
        )

    chains = {
        chain["name"]: chain
        for chain in structural["chains"]
        if chain["table"] == table
    }

    base_chain = chains.get(normalized_hook)
    if base_chain is None or base_chain["policy"] == "-":
        return result(
            "INCONCLUSIVE",
            "base_chain",
            "requested_base_chain_not_found",
            [],
        )

    base_policy = base_chain["policy"]
    if base_policy not in {"ACCEPT", "DROP"}:
        return result(
            "INCONCLUSIVE",
            "base_chain",
            "base_chain_policy_is_not_supported",
            [],
        )

    rules_by_chain: dict[str, list[RuleIR]] = {
        name: [] for name in chains
    }
    for rule in rules:
        if rule.table == table and rule.chain in rules_by_chain:
            rules_by_chain[rule.chain].append(rule)

    trace: list[TraceStep] = []
    active_chains: set[str] = set()
    internal_return = "RETURN"

    def walk_chain(chain_name: str, depth: int) -> tuple[str, str, str]:
        if depth > max_chain_depth:
            return (
                "INCONCLUSIVE",
                "execution_limit",
                "maximum_chain_depth_exceeded",
            )

        if chain_name in active_chains:
            return (
                "INCONCLUSIVE",
                "chain_recursion",
                "recursive_chain_reference_detected",
            )

        if chain_name not in chains:
            return (
                "INCONCLUSIVE",
                "chain_reference",
                "referenced_chain_not_found",
            )

        active_chains.add(chain_name)
        try:
            for rule in rules_by_chain.get(chain_name, []):
                if len(trace) >= max_steps:
                    return (
                        "INCONCLUSIVE",
                        "execution_limit",
                        "maximum_rule_evaluation_steps_exceeded",
                    )

                match_result, match_reason = _match_rule(rule, packet)

                if match_result == "NO_MATCH":
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="no_match",
                        reason=match_reason,
                    ))
                    continue

                if match_result == "UNKNOWN":
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="inconclusive",
                        reason=match_reason,
                    ))
                    return (
                        "INCONCLUSIVE",
                        "rule_interpretation",
                        "a_reachable_rule_could_not_be_evaluated",
                    )

                target = rule.target
                if target is None:
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="inconclusive",
                        reason="missing_target",
                    ))
                    return (
                        "INCONCLUSIVE",
                        "rule_target",
                        "matching_rule_has_no_supported_target",
                    )

                target_upper = target.upper()
                if target_upper in TERMINAL_VERDICTS:
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="match",
                        reason="terminal_verdict",
                        action=target_upper,
                    ))
                    return target_upper, "rule", "matching_rule_terminal_verdict"

                if target_upper == "RETURN":
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="match",
                        reason="return_to_caller",
                        action="RETURN",
                    ))
                    return internal_return, "rule", "explicit_return"

                if target not in chains:
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="inconclusive",
                        reason="unsupported_or_missing_chain_target",
                    ))
                    return (
                        "INCONCLUSIVE",
                        "rule_target",
                        "matching_rule_uses_an_unsupported_target",
                    )

                if rule.target_operation not in {"jump", "goto"}:
                    trace.append(TraceStep(
                        chain=chain_name,
                        line_number=rule.line_number,
                        result="inconclusive",
                        reason="unsupported_chain_transfer_operation",
                    ))
                    return (
                        "INCONCLUSIVE",
                        "rule_target",
                        "chain_transfer_operation_is_not_supported",
                    )

                trace.append(TraceStep(
                    chain=chain_name,
                    line_number=rule.line_number,
                    result="match",
                    reason="chain_transfer",
                    action=rule.target_operation,
                ))

                child_status, child_source, child_reason = walk_chain(
                    target,
                    depth + 1,
                )

                if child_status == "INCONCLUSIVE":
                    return child_status, child_source, child_reason

                if child_status == internal_return:
                    if rule.target_operation == "jump":
                        continue
                    return internal_return, "rule", "goto_target_returned"

                return child_status, child_source, child_reason

            chain_policy = chains[chain_name]["policy"]
            if chain_policy != "-":
                if chain_policy in {"ACCEPT", "DROP"}:
                    return (
                        chain_policy,
                        "base_chain_policy",
                        "base_chain_policy_applied",
                    )
                return (
                    "INCONCLUSIVE",
                    "base_chain_policy",
                    "unsupported_base_chain_policy",
                )

            return internal_return, "chain", "user_chain_returned"

        finally:
            active_chains.remove(chain_name)

    status, decision_source, reason = walk_chain(normalized_hook, 1)

    if status == internal_return:
        status = base_policy
        decision_source = "base_chain_policy"
        reason = "base_chain_policy_applied_after_return"

    return result(status, decision_source, reason, trace)
