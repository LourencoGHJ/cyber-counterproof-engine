"""Representação intermédia conservadora de regras iptables-save.

A IR normaliza apenas campos reconhecidos. Extensões e opções não suportadas
são assinaladas explicitamente; não são interpretadas como condições neutras.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import asdict, dataclass
from typing import Any

from cce.iptables_save import parse_iptables_save


SCHEMA_VERSION = "1.0"

SUPPORTED_MODULES = {
    "tcp",
    "udp",
    "multiport",
    "conntrack",
    "state",
    "comment",
}

SUPPORTED_PROTOCOLS = {
    "all",
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "ipv6-icmp",
    "sctp",
    "udplite",
}

SUPPORTED_CONNECTION_STATES = {
    "INVALID",
    "NEW",
    "ESTABLISHED",
    "RELATED",
    "UNTRACKED",
    "SNAT",
    "DNAT",
}

CORE_VERDICTS = {"ACCEPT", "DROP", "REJECT", "RETURN"}

VALUE_OPTIONS = {
    "-p": 1,
    "--protocol": 1,
    "-s": 1,
    "--source": 1,
    "-d": 1,
    "--destination": 1,
    "-i": 1,
    "--in-interface": 1,
    "-o": 1,
    "--out-interface": 1,
    "--sport": 1,
    "--source-port": 1,
    "--sports": 1,
    "--dport": 1,
    "--destination-port": 1,
    "--dports": 1,
    "--ports": 1,
    "--ctstate": 1,
    "--state": 1,
    "--comment": 1,
    "--limit": 1,
    "--limit-burst": 1,
    "--tcp-flags": 2,
    "--icmp-type": 1,
    "--icmpv6-type": 1,
    "--reject-with": 1,
    "--log-prefix": 1,
    "--log-level": 1,
    "--to-destination": 1,
    "--to-source": 1,
    "--to-ports": 1,
    "--mark": 1,
    "--set-mark": 1,
    "--uid-owner": 1,
    "--gid-owner": 1,
    "--physdev-in": 1,
    "--physdev-out": 1,
    "--name": 1,
    "--seconds": 1,
    "--hitcount": 1,
}

FLAG_OPTIONS = {
    "-f": "fragment_only",
    "--fragment": "fragment_only",
    "--syn": "tcp_syn_only",
}

IGNORED_METADATA_OPTIONS = {"--comment"}

PORT_OPTION_FIELDS = {
    "--sport": "source_ports",
    "--source-port": "source_ports",
    "--sports": "source_ports",
    "--dport": "destination_ports",
    "--destination-port": "destination_ports",
    "--dports": "destination_ports",
    "--ports": "either_ports",
}


@dataclass(frozen=True, slots=True)
class PortRange:
    """Intervalo inclusivo de portas."""

    first: int
    last: int

    def to_dict(self) -> dict[str, int]:
        return {"first": self.first, "last": self.last}


@dataclass(frozen=True, slots=True)
class RuleIR:
    """Regra normalizada; não contém a linha original do snapshot."""

    schema_version: str
    family: str
    table: str
    chain: str
    line_number: int
    protocol: str | None
    source: str | None
    destination: str | None
    input_interface: str | None
    output_interface: str | None
    source_ports: tuple[PortRange, ...]
    destination_ports: tuple[PortRange, ...]
    either_ports: tuple[PortRange, ...]
    connection_states: tuple[str, ...]
    modules: tuple[str, ...]
    target: str | None
    target_operation: str | None
    fragment_only: bool | None
    tcp_syn_only: bool | None
    negated_conditions: tuple[str, ...]
    unsupported_modules: tuple[str, ...]
    unsupported_options: tuple[str, ...]
    unsupported_targets: tuple[str, ...]
    warnings: tuple[str, ...]
    interpretation: str

    def to_dict(self) -> dict[str, Any]:
        """Converte a IR num objeto simples compatível com JSON."""
        result = asdict(self)
        for field in (
            "source_ports",
            "destination_ports",
            "either_ports",
        ):
            result[field] = [
                port.to_dict() if isinstance(port, PortRange) else port
                for port in getattr(self, field)
            ]

        for field in (
            "connection_states",
            "modules",
            "negated_conditions",
            "unsupported_modules",
            "unsupported_options",
            "unsupported_targets",
            "warnings",
        ):
            result[field] = list(getattr(self, field))

        return result


def _unique_append(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _parse_port_ranges(value: str) -> tuple[PortRange, ...] | None:
    """Interpreta portas numéricas e intervalos no formato iptables.

    Nomes de serviços e formatos ambíguos devolvem None.
    """
    ranges: list[PortRange] = []

    for item in value.split(","):
        item = item.strip()
        if not item:
            return None

        if ":" in item:
            if item.count(":") != 1:
                return None

            first_text, last_text = item.split(":", 1)
            try:
                first = int(first_text) if first_text else 0
                last = int(last_text) if last_text else 65535
            except ValueError:
                return None
        else:
            try:
                first = last = int(item)
            except ValueError:
                return None

        if not (0 <= first <= last <= 65535):
            return None

        ranges.append(PortRange(first=first, last=last))

    return tuple(ranges)


def _normalise_network(
    value: str,
    family: str,
) -> str | None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None

    expected_version = 4 if family == "ipv4" else 6
    if network.version != expected_version:
        return None

    return network.with_prefixlen


def _parse_rule_tokens(
    tokens: list[str],
    family: str,
    table: str,
    line_number: int,
    declared_chains: set[str],
) -> RuleIR:
    if len(tokens) < 3 or tokens[0] != "-A":
        raise ValueError(f"Regra inválida na linha {line_number}.")

    chain = tokens[1]
    if chain not in declared_chains:
        raise ValueError(
            f"Cadeia de origem inexistente na linha {line_number}."
        )

    protocol: str | None = None
    source: str | None = None
    destination: str | None = None
    input_interface: str | None = None
    output_interface: str | None = None

    source_ports: list[PortRange] = []
    destination_ports: list[PortRange] = []
    either_ports: list[PortRange] = []
    connection_states: list[str] = []
    modules: list[str] = []
    unsupported_modules: list[str] = []
    unsupported_options: list[str] = []
    unsupported_targets: list[str] = []
    warnings: list[str] = []
    negated_conditions: list[str] = []

    target: str | None = None
    target_operation: str | None = None
    fragment_only: bool | None = None
    tcp_syn_only: bool | None = None
    saw_ctstate = False
    saw_state = False
    saw_multiport_selector = False

    index = 2
    while index < len(tokens):
        token = tokens[index]

        if token == "!":
            if index + 1 >= len(tokens):
                _unique_append(warnings, "dangling_negation")
                index += 1
                continue
            negated = True
            index += 1
            token = tokens[index]
        else:
            negated = False

        option, inline_value = token, None
        if token.startswith("-") and "=" in token:
            option, inline_value = token.split("=", 1)

        if option in {"-j", "--jump", "-g", "--goto"}:
            if inline_value is not None:
                target_value = inline_value
                index += 1
            elif index + 1 < len(tokens):
                target_value = tokens[index + 1]
                index += 2
            else:
                _unique_append(warnings, "missing_target")
                index += 1
                continue

            if negated:
                _unique_append(warnings, "negated_target")
            if target is not None:
                _unique_append(warnings, "multiple_targets")
                continue

            target_operation = (
                "goto" if option in {"-g", "--goto"} else "jump"
            )
            if target_value.upper() in CORE_VERDICTS:
                target = target_value.upper()
            else:
                target = target_value
                if target_value not in declared_chains:
                    _unique_append(unsupported_targets, target_value)
            continue

        if option in {"-m", "--match"}:
            if inline_value is not None:
                module = inline_value
                index += 1
            elif index + 1 < len(tokens):
                module = tokens[index + 1]
                index += 2
            else:
                _unique_append(warnings, "missing_module_value")
                index += 1
                continue

            module = module.lower()
            _unique_append(modules, module)
            if module not in SUPPORTED_MODULES:
                _unique_append(unsupported_modules, module)
            if negated:
                _unique_append(warnings, "negated_match_module")
            continue

        if option in FLAG_OPTIONS:
            field = FLAG_OPTIONS[option]
            if field == "fragment_only":
                fragment_only = not negated
            else:
                tcp_syn_only = not negated
            if negated:
                _unique_append(negated_conditions, field)
            index += 1
            continue

        if option in VALUE_OPTIONS:
            arity = VALUE_OPTIONS[option]
            if inline_value is not None:
                values = [inline_value]
                index += 1
                if arity > 1:
                    extra = tokens[index:index + arity - 1]
                    values.extend(extra)
                    index += len(extra)
            else:
                value_index = index + 1
                if (
                    value_index < len(tokens)
                    and tokens[value_index] == "!"
                ):
                    negated = not negated
                    value_index += 1

                values = tokens[value_index:value_index + arity]
                index = value_index + len(values)

            if len(values) != arity:
                _unique_append(
                    warnings,
                    f"missing_value:{option}",
                )
                _unique_append(unsupported_options, option)
                continue

            value = values[0]

            if option in IGNORED_METADATA_OPTIONS:
                # Comentários não são condições de correspondência.
                continue

            if option in {"-p", "--protocol"}:
                candidate = value.lower()
                if candidate not in SUPPORTED_PROTOCOLS:
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, "unsupported_protocol")
                if protocol is not None and protocol != candidate:
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, "conflicting_protocols")
                else:
                    protocol = candidate
                if negated:
                    _unique_append(negated_conditions, "protocol")
                continue

            if option in {"-s", "--source", "-d", "--destination"}:
                field = (
                    "source"
                    if option in {"-s", "--source"}
                    else "destination"
                )
                network = _normalise_network(value, family)
                if network is None:
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, f"unparsed_network:{field}")
                else:
                    previous = source if field == "source" else destination
                    if previous is not None and previous != network:
                        _unique_append(unsupported_options, option)
                        _unique_append(warnings, f"multiple_{field}_selectors")
                    elif field == "source":
                        source = network
                    else:
                        destination = network
                if negated:
                    _unique_append(negated_conditions, field)
                continue

            if option in {"-i", "--in-interface", "-o", "--out-interface"}:
                field = (
                    "input_interface"
                    if option in {"-i", "--in-interface"}
                    else "output_interface"
                )
                if not value:
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, f"empty_{field}")
                else:
                    previous = (
                        input_interface
                        if field == "input_interface"
                        else output_interface
                    )
                    if previous is not None and previous != value:
                        _unique_append(unsupported_options, option)
                        _unique_append(warnings, f"multiple_{field}_selectors")
                    elif field == "input_interface":
                        input_interface = value
                    else:
                        output_interface = value
                if negated:
                    _unique_append(negated_conditions, field)
                continue

            if option in PORT_OPTION_FIELDS:
                is_multiport_option = option in {
                    "--sports", "--dports", "--ports"
                }
                if is_multiport_option:
                    saw_multiport_selector = True
                parsed_ranges = (
                    None
                    if "," in value and not is_multiport_option
                    else _parse_port_ranges(value)
                )
                if parsed_ranges is None:
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, "unresolved_port_specification")
                else:
                    destination_field = PORT_OPTION_FIELDS[option]
                    if destination_field == "source_ports":
                        source_ports.extend(parsed_ranges)
                    elif destination_field == "destination_ports":
                        destination_ports.extend(parsed_ranges)
                    else:
                        either_ports.extend(parsed_ranges)
                if negated:
                    _unique_append(
                        negated_conditions,
                        PORT_OPTION_FIELDS[option],
                    )
                continue

            if option in {"--ctstate", "--state"}:
                if option == "--ctstate":
                    saw_ctstate = True
                else:
                    saw_state = True
                states = [
                    state.strip().upper()
                    for state in value.split(",")
                    if state.strip()
                ]
                if (
                    not states
                    or any(
                        state not in SUPPORTED_CONNECTION_STATES
                        for state in states
                    )
                ):
                    _unique_append(unsupported_options, option)
                    _unique_append(warnings, "unsupported_connection_state")
                else:
                    for state in states:
                        _unique_append(connection_states, state)
                if negated:
                    _unique_append(negated_conditions, "connection_states")
                continue

            # A opção é reconhecida como tendo argumento, mas a sua
            # semântica ainda não faz parte da IR.
            _unique_append(unsupported_options, option)
            if negated:
                _unique_append(negated_conditions, option)
            continue

        if option.startswith("-"):
            # Opção desconhecida: guardar apenas o nome, nunca o valor.
            _unique_append(unsupported_options, option)
            if negated:
                _unique_append(negated_conditions, option)

            index += 1
            if index < len(tokens) and not tokens[index].startswith("-"):
                index += 1
            continue

        _unique_append(warnings, "unexpected_token")
        index += 1

    if target is None:
        _unique_append(warnings, "missing_target")

    transport_modules = {
        module for module in modules if module in {"tcp", "udp"}
    }
    if protocol is None and len(transport_modules) == 1:
        protocol = next(iter(transport_modules))
    elif len(transport_modules) > 1:
        _unique_append(warnings, "conflicting_transport_modules")
    elif protocol is not None and transport_modules and protocol not in transport_modules:
        _unique_append(warnings, "protocol_module_mismatch")

    has_port_conditions = bool(
        source_ports or destination_ports or either_ports
    )
    if has_port_conditions and protocol not in {"tcp", "udp"}:
        _unique_append(warnings, "port_selector_without_transport_protocol")
    if saw_multiport_selector and "multiport" not in modules:
        _unique_append(warnings, "multiport_selector_without_module")
    if "multiport" in modules and protocol not in {"tcp", "udp"}:
        _unique_append(warnings, "multiport_without_supported_transport")
    if tcp_syn_only is not None and protocol != "tcp":
        _unique_append(warnings, "tcp_syn_without_tcp_protocol")
    if saw_ctstate and "conntrack" not in modules:
        _unique_append(warnings, "ctstate_without_conntrack_module")
    if saw_state and "state" not in modules:
        _unique_append(warnings, "state_without_state_module")
    if fragment_only and family == "ipv6":
        _unique_append(warnings, "ipv4_fragment_match_in_ipv6_snapshot")

    interpretation = (
        "complete"
        if not (
            unsupported_modules
            or unsupported_options
            or unsupported_targets
            or warnings
        )
        else "partial"
    )

    return RuleIR(
        schema_version=SCHEMA_VERSION,
        family=family,
        table=table,
        chain=chain,
        line_number=line_number,
        protocol=protocol,
        source=source,
        destination=destination,
        input_interface=input_interface,
        output_interface=output_interface,
        source_ports=tuple(source_ports),
        destination_ports=tuple(destination_ports),
        either_ports=tuple(either_ports),
        connection_states=tuple(connection_states),
        modules=tuple(modules),
        target=target,
        target_operation=target_operation,
        fragment_only=fragment_only,
        tcp_syn_only=tcp_syn_only,
        negated_conditions=tuple(negated_conditions),
        unsupported_modules=tuple(unsupported_modules),
        unsupported_options=tuple(unsupported_options),
        unsupported_targets=tuple(unsupported_targets),
        warnings=tuple(warnings),
        interpretation=interpretation,
    )


def parse_iptables_rules_ir(
    snapshot_text: str,
    family: str,
) -> list[RuleIR]:
    """Converte regras de um snapshot iptables-save para a IR.

    A função valida primeiro a estrutura do snapshot com o parser existente.
    Linhas estruturalmente malformadas impedem a conversão, para não produzir
    uma representação incompleta que pareça fiável.
    """
    structural = parse_iptables_save(snapshot_text, family)
    malformed = structural["summary"]["malformed_lines"]
    if malformed:
        raise ValueError(
            f"O snapshot contém {malformed} linha(s) estruturalmente malformada(s)."
        )

    declared_by_table: dict[str, set[str]] = {}
    for chain in structural["chains"]:
        declared_by_table.setdefault(chain["table"], set()).add(chain["name"])

    rules: list[RuleIR] = []
    current_table: str | None = None

    for line_number, raw in enumerate(snapshot_text.splitlines(), start=1):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            current_table = line[1:].strip()
            continue

        if line == "COMMIT":
            current_table = None
            continue

        if current_table is None or not line.startswith("-A "):
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise ValueError(
                f"Não foi possível interpretar a regra na linha {line_number}."
            ) from exc

        rules.append(
            _parse_rule_tokens(
                tokens=tokens,
                family=family,
                table=current_table,
                line_number=line_number,
                declared_chains=declared_by_table.get(current_table, set()),
            )
        )

    expected_rules = structural["summary"]["rules_total"]
    if len(rules) != expected_rules:
        raise ValueError(
            "O número de regras convertidas para IR não corresponde "
            "ao número de regras do parser estrutural."
        )

    return rules


def build_iptables_ir_document(
    snapshot_text: str,
    family: str,
) -> dict[str, Any]:
    """Produz um documento IR com métricas de interpretação."""
    rules = parse_iptables_rules_ir(snapshot_text, family)
    complete = sum(rule.interpretation == "complete" for rule in rules)
    partial = len(rules) - complete

    return {
        "schema_version": SCHEMA_VERSION,
        "source_format": "iptables-save",
        "family": family,
        "summary": {
            "rules_total": len(rules),
            "rules_fully_interpreted": complete,
            "rules_partially_interpreted": partial,
        },
        "rules": [rule.to_dict() for rule in rules],
        "limitations": [
            "A IR normaliza condições reconhecidas; não calcula ainda o resultado do tráfego.",
            "Opções, módulos e targets não suportados são assinalados e não são tratados como neutros.",
            "Os valores de rede e interface incluídos na IR podem ser sensíveis; não publicar documentos derivados de snapshots reais.",
        ],
    }
