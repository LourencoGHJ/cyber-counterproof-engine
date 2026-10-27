"""Análise estrutural de chains num snapshot JSON do nftables.

Não avalia a semântica completa das regras nem altera o sistema.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Any

ChainKey = tuple[str, str, str]


def _identity(record: dict[str, Any], context: str) -> ChainKey:
    """Obtém a identidade de uma chain ou regra."""
    values = (
        record.get("family"),
        record.get("table"),
        record.get("name")
        if context == "chain"
        else record.get("chain"),
    )

    if not all(
        isinstance(value, str) and value.strip()
        for value in values
    ):
        raise ValueError(f"Identidade inválida em {context}.")

    return values


def analyze_chain_graph(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Constrói um grafo usando apenas referências explícitas jump/goto."""
    if not isinstance(snapshot, dict):
        raise ValueError("O snapshot tem de ser um objeto JSON.")

    elements = snapshot.get("nftables")
    if not isinstance(elements, list):
        raise ValueError("O snapshot não contém uma lista nftables válida.")

    chains: dict[ChainKey, dict[str, Any]] = {}

    # Primeira passagem: inventariar todas as chains.
    for index, element in enumerate(elements):
        if not isinstance(element, dict) or not element:
            raise ValueError(f"Elemento inválido no índice {index}.")

        if "chain" not in element:
            continue

        chain = element["chain"]
        if not isinstance(chain, dict):
            raise ValueError(f"Chain inválida no índice {index}.")

        key = _identity(chain, "chain")

        if key in chains:
            raise ValueError(
                f"Chain duplicada no snapshot: {key[0]}/{key[1]}/{key[2]}."
            )

        chains[key] = chain

    adjacency: dict[ChainKey, set[ChainKey]] = {
        key: set() for key in chains
    }
    rule_counts: Counter[ChainKey] = Counter()
    expression_kinds: Counter[str] = Counter()

    jump_edges: list[dict[str, Any]] = []
    goto_edges: list[dict[str, Any]] = []
    dangling_targets: list[dict[str, Any]] = []

    rules_total = 0
    rules_with_xt = 0
    xt_expressions = 0
    unknown_expression_nodes = 0

    # Segunda passagem: analisar regras e referências.
    for index, element in enumerate(elements):
        if "rule" not in element:
            continue

        rule = element["rule"]
        if not isinstance(rule, dict):
            raise ValueError(f"Regra inválida no índice {index}.")

        source = _identity(rule, "rule")

        if source not in chains:
            raise ValueError(
                "Uma regra referencia uma chain de origem ausente "
                f"no snapshot: {source[0]}/{source[1]}/{source[2]}."
            )

        expressions = rule.get("expr", [])
        if not isinstance(expressions, list):
            raise ValueError(
                f"A lista de expressões da regra {index} é inválida."
            )

        rules_total += 1
        rule_counts[source] += 1
        rule_has_xt = False

        for expression in expressions:
            if not isinstance(expression, dict) or not expression:
                unknown_expression_nodes += 1
                continue

            for operation, body in expression.items():
                expression_kinds[str(operation)] += 1

                if operation == "xt":
                    xt_expressions += 1
                    rule_has_xt = True

                if operation not in {"jump", "goto"}:
                    continue

                if not isinstance(body, dict):
                    raise ValueError(
                        f"Referência {operation} inválida na regra {index}."
                    )

                target = body.get("target")
                if not isinstance(target, str) or not target.strip():
                    raise ValueError(
                        f"Destino {operation} inválido na regra {index}."
                    )

                destination: ChainKey = (
                    source[0],
                    source[1],
                    target,
                )
                resolved = destination in chains

                edge = {
                    "family": source[0],
                    "table": source[1],
                    "source": source[2],
                    "operation": operation,
                    "target": target,
                    "resolved": resolved,
                }

                if operation == "jump":
                    jump_edges.append(edge)
                else:
                    goto_edges.append(edge)

                if resolved:
                    adjacency[source].add(destination)
                else:
                    dangling_targets.append(edge)

        if rule_has_xt:
            rules_with_xt += 1

    # Todas as base chains são pontos de entrada do grafo.
    roots = {
        key
        for key, chain in chains.items()
        if isinstance(chain.get("hook"), str)
        and bool(chain["hook"])
    }

    reachable: set[ChainKey] = set()
    pending = deque(sorted(roots))

    while pending:
        current = pending.popleft()

        if current in reachable:
            continue

        reachable.add(current)
        pending.extend(sorted(adjacency[current] - reachable))

    def describe(key: ChainKey) -> dict[str, Any]:
        chain = chains[key]
        return {
            "family": key[0],
            "table": key[1],
            "chain": key[2],
            "hook": chain.get("hook"),
            "reachable_via_explicit_jump_goto": key in reachable,
            "rule_count": rule_counts[key],
        }

    unreachable_chains = [
        describe(key)
        for key in sorted(chains)
        if key not in reachable
        and not chains[key].get("hook")
    ]

    return {
        "scope": "explicit_jump_goto_references",
        "summary": {
            "chains_total": len(chains),
            "base_chains": len(roots),
            "reachable_chains": len(reachable),
            "chains_without_explicit_path": len(unreachable_chains),
            "rules_total": rules_total,
            "jump_references": len(jump_edges),
            "goto_references": len(goto_edges),
            "dangling_targets": len(dangling_targets),
            "rules_with_xt": rules_with_xt,
            "xt_expressions": xt_expressions,
            "unknown_expression_nodes": unknown_expression_nodes,
        },
        "chains": [describe(key) for key in sorted(chains)],
        "jump_edges": jump_edges,
        "goto_edges": goto_edges,
        "dangling_targets": dangling_targets,
        "chains_without_explicit_path": unreachable_chains,
        "expression_kinds": dict(sorted(expression_kinds.items())),
        "limitations": [
            "Só são seguidas referências explícitas jump e goto.",
            "Expressões xt não são interpretadas.",
            "A ausência de caminho explícito não prova que uma chain esteja realmente inacessível.",
            "A acessibilidade estrutural não equivale a uma análise de tráfego.",
        ],
    }
