"""Deteção heurística de regras potencialmente arriscadas em snapshots."""

from __future__ import annotations

import ipaddress
import shlex
from typing import Any

from cce.iptables_save import parse_iptables_save


def _port_spec_includes_ssh(value: str) -> bool:
    """Verifica se uma especificação de portas inclui TCP/22."""
    for item in value.split(","):
        item = item.strip().lower()

        if item == "ssh" or item == "22":
            return True

        separator = ":" if ":" in item else (
            "-" if "-" in item else None
        )
        if separator is None:
            continue

        lower, upper = item.split(separator, 1)

        try:
            start = int(lower) if lower else 0
            end = int(upper) if upper else 65535
        except ValueError:
            continue

        if 0 <= start <= 22 <= end <= 65535:
            return True

    return False


def _has_positive_source_restriction(tokens: list[str]) -> bool:
    """Verifica se a regra tem uma origem explícita e restritiva."""
    source_options = {"-s", "--source"}

    for index, token in enumerate(tokens):
        if token not in source_options:
            continue

        value_index = index + 1
        negated = index > 0 and tokens[index - 1] == "!"

        if value_index < len(tokens) and tokens[value_index] == "!":
            negated = True
            value_index += 1

        if negated:
            continue

        if value_index >= len(tokens):
            return False

        try:
            network = ipaddress.ip_network(
                tokens[value_index],
                strict=False,
            )
        except ValueError:
            # Não declarar a regra sem restrição se o valor de origem
            # explícito não puder ser interpretado.
            return True

        if network.prefixlen > 0:
            return True

    return False


def find_ssh_rule_candidates(
    snapshot_text: str,
    family: str,
) -> list[dict[str, Any]]:
    """Deteta candidatos SSH/TCP/22 sem origem positiva restritiva.

    Analisa um snapshot fornecido. Não executa comandos nem altera regras.
    Os resultados são candidatos heurísticos, não provas de acessibilidade.
    """
    parsed = parse_iptables_save(snapshot_text, family)

    filter_chains = {
        chain["name"]
        for chain in parsed["chains"]
        if chain["table"] == "filter"
    }

    adjacency: dict[str, set[str]] = {
        name: set() for name in filter_chains
    }

    for edge in parsed["chain_edges"]:
        if (
            edge["table"] == "filter"
            and edge["source"] in adjacency
            and edge["target"] in filter_chains
        ):
            adjacency[edge["source"]].add(edge["target"])

    # Considera apenas chains alcançáveis por saltos explícitos a partir
    # da chain INPUT. Não avalia todas as condições das chains chamadoras.
    reachable: set[str] = set()
    pending = ["INPUT"] if "INPUT" in filter_chains else []

    while pending:
        current = pending.pop()

        if current in reachable:
            continue

        reachable.add(current)
        pending.extend(adjacency.get(current, set()) - reachable)

    candidates: list[dict[str, Any]] = []
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

        if current_table != "filter" or not line.startswith("-A "):
            continue

        try:
            tokens = shlex.split(line)
        except ValueError:
            continue

        if len(tokens) < 3 or tokens[0] != "-A":
            continue

        chain = tokens[1]
        if chain not in reachable:
            continue

        protocol_tcp = False
        modules: set[str] = set()
        accepts = False
        matches_ssh_port = False

        for index, token in enumerate(tokens):
            if token in {"-p", "--protocol"} and index + 1 < len(tokens):
                protocol_tcp = (
                    protocol_tcp or tokens[index + 1].lower() == "tcp"
                )

            elif token in {"-m", "--match"} and index + 1 < len(tokens):
                modules.add(tokens[index + 1].lower())

            elif (
                token in {"-j", "--jump"}
                and index + 1 < len(tokens)
                and tokens[index + 1].upper() == "ACCEPT"
            ):
                accepts = True

            elif token in {
                "--dport", "--destination-port", "--dports"
            }:
                value_index = index + 1
                negated = index > 0 and tokens[index - 1] == "!"

                if (
                    value_index < len(tokens)
                    and tokens[value_index] == "!"
                ):
                    negated = True
                    value_index += 1

                if (
                    not negated
                    and value_index < len(tokens)
                    and _port_spec_includes_ssh(tokens[value_index])
                ):
                    matches_ssh_port = True

        protocol_tcp = protocol_tcp or "tcp" in modules

        if not (
            accepts
            and protocol_tcp
            and matches_ssh_port
            and not _has_positive_source_restriction(tokens)
        ):
            continue

        is_input_chain = chain == "INPUT"

        candidates.append({
            "code": "CCE-IPTABLES-SSH-22-SOURCE-UNRESTRICTED-CANDIDATE",
            "severity": "medium" if is_input_chain else "low",
            "confidence": "candidate",
            "family": family,
            "table": "filter",
            "chain": chain,
            "line_number": line_number,
            "service": "SSH",
            "protocol": "tcp",
            "destination_port": 22,
            "reason": (
                "Regra ACCEPT para TCP/22 sem restrição positiva de "
                "origem detetada na própria regra."
            ),
            "context_note": (
                "A ordem das regras, o estado do serviço e o contexto "
                "integral do tráfego não foram avaliados."
            ),
            "rule_text_included": False,
        })

    return candidates
