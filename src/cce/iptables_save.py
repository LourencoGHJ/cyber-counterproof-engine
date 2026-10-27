"""Parser estrutural, conservador, para snapshots iptables-save."""

from __future__ import annotations

import shlex
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any


KNOWN_TARGETS = {
    "ACCEPT", "DROP", "REJECT", "RETURN", "LOG",
    "QUEUE", "NFQUEUE", "NFLOG", "ULOG", "TRACE",
    "DNAT", "SNAT", "MASQUERADE", "REDIRECT", "TPROXY",
    "MARK", "CONNMARK", "CT", "NOTRACK", "SECMARK",
    "CONNSECMARK", "TCPMSS", "TTL", "HL", "DSCP",
    "CLASSIFY", "AUDIT", "CHECKSUM", "LED", "RATEEST",
    "SET", "SYNPROXY", "HMARK", "NETMAP", "DNPT",
    "SNPT", "TEE", "BALANCE", "IDLETIMER", "ECN",
}

VALUE_OPTIONS = {
    "-s", "--source", "-d", "--destination",
    "-i", "--in-interface", "-o", "--out-interface",
    "--sport", "--source-port", "--dport", "--destination-port",
    "--ctstate", "--state", "--icmp-type", "--icmpv6-type",
    "--limit", "--limit-burst", "--log-prefix",
    "--reject-with", "--hl-eq", "--rt-type",
    "--comment", "--tcp-flags", "--to-destination",
    "--to-source", "--mark", "--uid-owner", "--gid-owner",
    "--physdev-in", "--physdev-out",
}

HOOK_FIELDS = {
    "INPUT": "input_policy",
    "OUTPUT": "output_policy",
    "FORWARD": "forward_policy",
}


def parse_iptables_save(text: str, family: str) -> dict[str, Any]:
    """Analisa um snapshot já recolhido; não executa comandos do sistema."""
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("family tem de ser 'ipv4' ou 'ipv6'.")

    if not isinstance(text, str) or not text.strip():
        raise ValueError("O snapshot iptables-save está vazio.")

    current_table: str | None = None
    tables: set[str] = set()
    chains: dict[tuple[str, str], dict[str, Any]] = {}
    rules: list[dict[str, Any]] = []
    malformed_lines = 0

    module_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    target_counts: Counter[str] = Counter()
    option_counts: Counter[str] = Counter()

    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            table = line[1:].strip()
            if not table:
                malformed_lines += 1
                current_table = None
                continue
            current_table = table
            tables.add(table)
            continue

        if line == "COMMIT":
            current_table = None
            continue

        if line.startswith(":"):
            if current_table is None:
                malformed_lines += 1
                continue

            try:
                parts = shlex.split(line[1:])
            except ValueError:
                malformed_lines += 1
                continue

            if len(parts) < 2:
                malformed_lines += 1
                continue

            name, policy = parts[0], parts[1]
            key = (current_table, name)

            if key in chains:
                raise ValueError(
                    f"Chain duplicada na linha {line_number}: "
                    f"{current_table}/{name}."
                )

            chains[key] = {
                "table": current_table,
                "name": name,
                "policy": policy.upper(),
            }
            continue

        if not line.startswith("-A "):
            malformed_lines += 1
            continue

        if current_table is None:
            malformed_lines += 1
            continue

        try:
            tokens = shlex.split(line)
        except ValueError:
            malformed_lines += 1
            continue

        if len(tokens) < 3 or tokens[0] != "-A":
            malformed_lines += 1
            continue

        source_chain = tokens[1]
        rule: dict[str, Any] = {
            "table": current_table,
            "chain": source_chain,
            "line_number": line_number,
            "protocol": None,
            "modules": [],
            "options": [],
            "references": [],
        }

        index = 2
        while index < len(tokens):
            token = tokens[index]

            if token in {"-m", "--match", "-p", "--protocol",
                         "-j", "--jump", "-g", "--goto"}:
                if index + 1 >= len(tokens):
                    malformed_lines += 1
                    break

                value = tokens[index + 1]

                if token in {"-m", "--match"}:
                    module_counts[value] += 1
                    rule["modules"].append(value)

                elif token in {"-p", "--protocol"}:
                    protocol_counts[value] += 1
                    rule["protocol"] = value

                else:
                    operation = (
                        "jump" if token in {"-j", "--jump"} else "goto"
                    )
                    target_counts[value] += 1
                    rule["references"].append({
                        "operation": operation,
                        "target": value,
                    })

                index += 2
                continue

            if token.startswith("-"):
                option_counts[token] += 1
                rule["options"].append(token)

                if (
                    token in VALUE_OPTIONS
                    and index + 1 < len(tokens)
                ):
                    index += 2
                else:
                    index += 1
                continue

            index += 1

        rules.append(rule)

    if not chains:
        raise ValueError("O snapshot não contém declarações de chains.")

    # Validar as chains de origem depois de ler todas as declarações.
    for rule in rules:
        source = (rule["table"], rule["chain"])
        if source not in chains:
            raise ValueError(
                f"Regra na linha {rule['line_number']} referencia "
                f"a chain de origem inexistente {source[0]}/{source[1]}."
            )

    rule_counts: Counter[tuple[str, str]] = Counter()
    adjacency = {key: set() for key in chains}
    edges: list[dict[str, Any]] = []
    unresolved_targets: list[dict[str, Any]] = []
    rules_with_jump_goto_targets = 0
    rules_with_chain_references = 0

    for rule in rules:
        source = (rule["table"], rule["chain"])
        rule_counts[source] += 1

        if rule["references"]:
            rules_with_jump_goto_targets += 1

        has_chain_reference = False
        for reference in rule["references"]:
            target = reference["target"]
            destination = (rule["table"], target)

            if destination in chains:
                adjacency[source].add(destination)
                has_chain_reference = True
                edges.append({
                    "table": rule["table"],
                    "source": rule["chain"],
                    "operation": reference["operation"],
                    "target": target,
                    "line_number": rule["line_number"],
                })

            elif target.upper() not in KNOWN_TARGETS:
                # Pode ser uma chain em falta ou um target de extensão
                # que este parser não conhece. Não afirmamos qual deles.
                unresolved_targets.append({
                    "table": rule["table"],
                    "source": rule["chain"],
                    "operation": reference["operation"],
                    "target": target,
                    "line_number": rule["line_number"],
                })

        if has_chain_reference:
            rules_with_chain_references += 1

    roots = {
        key for key, chain in chains.items()
        if chain["policy"] != "-"
    }

    reachable: set[tuple[str, str]] = set()
    pending = deque(sorted(roots))

    while pending:
        current = pending.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(sorted(adjacency[current] - reachable))

    chain_results = []
    for key in sorted(chains):
        chain = chains[key]
        is_base = chain["policy"] != "-"

        chain_results.append({
            **chain,
            "is_base_chain": is_base,
            "rule_count": rule_counts[key],
            "reachable_via_explicit_jump_goto": key in reachable,
        })

    chains_without_path = [
        chain for chain in chain_results
        if not chain["is_base_chain"]
        and not chain["reachable_via_explicit_jump_goto"]
    ]

    return {
        "family": family,
        "scope": "iptables_save_structural_analysis",
        "summary": {
            "tables_total": len(tables),
            "chains_total": len(chains),
            "base_chains": len(roots),
            "rules_total": len(rules),
            "rules_with_jump_goto_targets": rules_with_jump_goto_targets,
            "rules_with_chain_references": rules_with_chain_references,
            "jump_references": sum(
                edge["operation"] == "jump" for edge in edges
            ),
            "goto_references": sum(
                edge["operation"] == "goto" for edge in edges
            ),
            "unresolved_targets": len(unresolved_targets),
            "chains_without_explicit_path": len(chains_without_path),
            "malformed_lines": malformed_lines,
        },
        "chains": chain_results,
        "chain_edges": edges,
        "unresolved_targets": unresolved_targets,
        "chains_without_explicit_path": chains_without_path,
        "match_modules": dict(sorted(module_counts.items())),
        "target_counts": dict(sorted(target_counts.items())),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "option_counts": dict(sorted(option_counts.items())),
        "limitations": [
            "O parser não interpreta todas as condições das regras.",
            "As opções são contabilizadas sem guardar os respetivos valores.",
            "Targets desconhecidos ficam por resolver; não são automaticamente considerados chains inexistentes.",
            "A acessibilidade considera apenas saltos explícitos para chains declaradas.",
            "A análise estrutural não equivale a uma avaliação semântica do tráfego.",
        ],
    }


def analyze_iptables_saves(
    policy: dict[str, Any],
    ipv4_text: str,
    ipv6_text: str,
) -> dict[str, Any]:
    """Compara políticas base de IPv4 e IPv6 sem aplicar regras."""
    if not isinstance(policy, dict):
        raise ValueError("A política esperada tem de ser um objeto JSON.")

    expected_policies = {}
    for hook, field in HOOK_FIELDS.items():
        if field not in policy:
            continue

        expected = policy[field]
        if not isinstance(expected, str) or expected.lower() not in {
            "accept", "drop"
        }:
            raise ValueError(
                f"{field} tem de ser 'accept' ou 'drop' nesta análise."
            )

        expected_policies[hook] = expected.upper()

    if not expected_policies:
        raise ValueError("A política não declara políticas base suportadas.")

    families = [
        parse_iptables_save(ipv4_text, "ipv4"),
        parse_iptables_save(ipv6_text, "ipv6"),
    ]

    findings: list[dict[str, Any]] = []
    unassessed_hooks: list[str] = []
    matched = 0

    for result in families:
        family = result["family"]

        for hook, field in HOOK_FIELDS.items():
            if field not in expected_policies and field not in policy:
                unassessed_hooks.append(f"{family}:{hook.lower()}")
                continue

            if hook not in expected_policies:
                continue

            expected = expected_policies[hook]
            chain = next(
                (
                    item for item in result["chains"]
                    if item["table"] == "filter"
                    and item["name"] == hook
                ),
                None,
            )

            if chain is None:
                findings.append({
                    "code": "CCE-IPTABLES-BASE-CHAIN-MISSING",
                    "severity": "medium",
                    "family": family,
                    "table": "filter",
                    "chain": hook,
                    "expected": expected,
                    "observed": None,
                })
                continue

            observed = chain["policy"]

            if observed == expected:
                matched += 1
            else:
                findings.append({
                    "code": "CCE-IPTABLES-BASE-POLICY-MISMATCH",
                    "severity": (
                        "high"
                        if hook == "INPUT"
                        and expected == "DROP"
                        and observed == "ACCEPT"
                        else "medium"
                    ),
                    "family": family,
                    "table": "filter",
                    "chain": hook,
                    "expected": expected,
                    "observed": observed,
                })

    total_rules = sum(
        result["summary"]["rules_total"] for result in families
    )
    total_chains = sum(
        result["summary"]["chains_total"] for result in families
    )
    unresolved = sum(
        result["summary"]["unresolved_targets"] for result in families
    )
    chains_without_path = sum(
        result["summary"]["chains_without_explicit_path"]
        for result in families
    )
    malformed = sum(
        result["summary"]["malformed_lines"] for result in families
    )

    # Sem regras interpretadas semanticamente, nunca declaramos PASS.
    status = "DRIFT" if findings else "INCONCLUSIVE"

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "scope": "base_policies_and_iptables_save_structure",
        "summary": {
            "families_total": len(families),
            "chains_total": total_chains,
            "rules_total": total_rules,
            "base_policies_matched": matched,
            "base_policy_mismatches": len(findings),
            "unassessed_hooks": unassessed_hooks,
            "unresolved_targets": unresolved,
            "chains_without_explicit_path": chains_without_path,
            "malformed_lines": malformed,
            "rules_semantically_compared": 0,
        },
        "findings": findings,
        "families": families,
        "limitations": [
            "A comparação de políticas abrange apenas INPUT, OUTPUT e FORWARD na tabela filter.",
            "As regras individuais ainda não são comparadas semanticamente com a política JSON.",
            "As opções e respetivos valores não são avaliados para decidir se um fluxo é permitido.",
            "Targets desconhecidos ficam inconclusivos até serem identificados.",
            "Os snapshots podem estar desatualizados relativamente ao estado atual.",
            "Não foi executado nenhum comando para alterar a firewall.",
        ],
    }
