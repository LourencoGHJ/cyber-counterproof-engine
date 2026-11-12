"""Conservative structural control-flow analysis for iptables-save chains."""

from __future__ import annotations

from collections import deque
from typing import Any

from cce.iptables_save import parse_iptables_save


def _strongly_connected_components(
    nodes: set[str],
    adjacency: dict[str, set[str]],
) -> list[list[str]]:
    """Return deterministic strongly connected components without recursion."""
    reverse: dict[str, set[str]] = {node: set() for node in nodes}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)

    visited: set[str] = set()
    finish_order: list[str] = []

    for root in sorted(nodes):
        if root in visited:
            continue

        visited.add(root)
        stack: list[tuple[str, Any]] = [
            (root, iter(sorted(adjacency.get(root, set()))))
        ]
        while stack:
            node, neighbors = stack[-1]
            try:
                neighbor = next(neighbors)
            except StopIteration:
                finish_order.append(node)
                stack.pop()
                continue

            if neighbor not in visited:
                visited.add(neighbor)
                stack.append(
                    (neighbor, iter(sorted(adjacency.get(neighbor, set()))))
                )

    visited.clear()
    components: list[list[str]] = []

    for root in reversed(finish_order):
        if root in visited:
            continue

        component: list[str] = []
        pending = [root]
        visited.add(root)
        while pending:
            node = pending.pop()
            component.append(node)
            for neighbor in sorted(reverse[node], reverse=True):
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)

        components.append(sorted(component))

    return sorted(components, key=lambda component: component[0])


def analyze_iptables_chain_flow(
    snapshot_text: str,
    family: str,
    table: str = "filter",
) -> dict[str, Any]:
    """Describe explicit chain-call flow, reachability and potential cycles.

    Reachability is structural: every explicit jump/goto edge is considered
    traversable, without evaluating the rule's packet selectors. Cycles are
    therefore potential recursion paths, not proof that a packet can traverse
    the complete cycle.
    """
    if family not in {"ipv4", "ipv6"}:
        raise ValueError("family tem de ser 'ipv4' ou 'ipv6'.")
    if not isinstance(table, str) or not table.strip():
        raise ValueError("table tem de ser texto não vazio.")

    structural = parse_iptables_save(snapshot_text, family)
    table_chains = [
        chain
        for chain in structural["chains"]
        if chain["table"] == table
    ]
    nodes = {chain["name"] for chain in table_chains}
    if not nodes:
        raise ValueError(f"O snapshot não contém chains na tabela {table}.")

    edges = sorted(
        (
            dict(edge)
            for edge in structural["chain_edges"]
            if edge["table"] == table
            and edge["source"] in nodes
            and edge["target"] in nodes
        ),
        key=lambda edge: (
            edge["line_number"],
            edge["source"],
            edge["target"],
            edge["operation"],
        ),
    )
    unresolved_targets = sorted(
        (
            dict(item)
            for item in structural["unresolved_targets"]
            if item["table"] == table
        ),
        key=lambda item: (
            item["line_number"],
            item["source"],
            item["target"],
        ),
    )

    adjacency: dict[str, set[str]] = {node: set() for node in nodes}
    for edge in edges:
        adjacency[edge["source"]].add(edge["target"])

    base_chains = sorted(
        chain["name"]
        for chain in table_chains
        if chain["policy"] != "-"
    )

    reachable: set[str] = set()
    pending = deque(base_chains)
    while pending:
        current = pending.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(sorted(adjacency[current] - reachable))

    incoming_counts = {node: 0 for node in nodes}
    outgoing_counts = {node: 0 for node in nodes}
    for edge in edges:
        outgoing_counts[edge["source"]] += 1
        incoming_counts[edge["target"]] += 1

    chain_records = []
    for chain in sorted(table_chains, key=lambda item: item["name"]):
        name = chain["name"]
        chain_records.append(
            {
                "chain": name,
                "policy": chain["policy"],
                "is_base_chain": chain["policy"] != "-",
                "rule_count": chain["rule_count"],
                "structurally_reachable": name in reachable,
                "incoming_references": incoming_counts[name],
                "outgoing_references": outgoing_counts[name],
            }
        )

    components = _strongly_connected_components(nodes, adjacency)
    cyclic_components: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for component in components:
        members = set(component)
        internal_edges = [
            edge
            for edge in edges
            if edge["source"] in members and edge["target"] in members
        ]
        is_cycle = len(component) > 1 or any(
            edge["source"] == edge["target"] for edge in internal_edges
        )
        if not is_cycle:
            continue

        component_id = f"CC{len(cyclic_components) + 1:04d}"
        cycle = {
            "id": component_id,
            "chains": component,
            "edges": internal_edges,
            "structurally_reachable_from_base": bool(members.intersection(reachable)),
        }
        cyclic_components.append(cycle)
        findings.append(
            {
                "id": f"CF{len(findings) + 1:04d}",
                "code": "POTENTIAL_CHAIN_RECURSION",
                "severity": "medium",
                "certainty": "potential",
                "component_id": component_id,
                "chains": component,
                "line_numbers": sorted(
                    {edge["line_number"] for edge in internal_edges}
                ),
                "structurally_reachable_from_base": cycle[
                    "structurally_reachable_from_base"
                ],
                "description": (
                    "Foi encontrado um ciclo nas referências explícitas entre "
                    "chains. As condições dos saltos não foram avaliadas; o ciclo "
                    "é um caminho estrutural potencial, não prova de recursão "
                    "executável para um pacote."
                ),
            }
        )

    unreachable_user_chains = sorted(
        chain["name"]
        for chain in table_chains
        if chain["policy"] == "-" and chain["name"] not in reachable
    )
    for name in unreachable_user_chains:
        findings.append(
            {
                "id": f"CF{len(findings) + 1:04d}",
                "code": "STRUCTURALLY_UNREACHABLE_CHAIN",
                "severity": "info",
                "certainty": "structural",
                "chain": name,
                "description": (
                    "Não foi encontrado um caminho de referências jump/goto "
                    "a partir de uma chain base da tabela analisada."
                ),
            }
        )

    findings.sort(
        key=lambda item: (
            item["code"],
            item.get("chains", [item.get("chain", "")])[0],
            item["id"],
        )
    )
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"CF{index:04d}"

    malformed_lines = structural["summary"]["malformed_lines"]
    return {
        "schema_version": "1.0",
        "family": family,
        "table": table,
        "analysis_status": "partial" if malformed_lines else "completed",
        "reachability_model": "structural_explicit_jump_goto",
        "summary": {
            "chains_total": len(nodes),
            "base_chains_total": len(base_chains),
            "structurally_reachable_chains_total": len(reachable),
            "structurally_reachable_user_chains": sum(
                chain["policy"] == "-"
                and chain["name"] in reachable
                for chain in table_chains
            ),
            "structurally_unreachable_user_chains": len(
                unreachable_user_chains
            ),
            "chain_references_total": len(edges),
            "jump_references": sum(
                edge["operation"] == "jump" for edge in edges
            ),
            "goto_references": sum(
                edge["operation"] == "goto" for edge in edges
            ),
            "unresolved_targets_total": len(unresolved_targets),
            "cyclic_components_total": len(cyclic_components),
            "potential_cycle_edges_total": sum(
                len(cycle["edges"]) for cycle in cyclic_components
            ),
            "malformed_lines": malformed_lines,
            "findings_total": len(findings),
        },
        "chains": chain_records,
        "edges": edges,
        "unresolved_targets": unresolved_targets,
        "cyclic_components": cyclic_components,
        "findings": findings,
        "limitations": [
            "A análise é estrutural e cobre apenas a tabela indicada.",
            "A alcançabilidade considera todas as referências explícitas jump/goto, sem avaliar as condições de correspondência das regras.",
            "Ciclos são assinalados como potenciais; não é provado que exista um pacote que percorra todas as arestas do ciclo.",
            "Targets não resolvidos não são automaticamente classificados como chains em falta, pois podem corresponder a extensões não reconhecidas.",
            "A análise não simula veredictos, RETURN, NAT, routing ou o comportamento do kernel.",
            "Nenhuma regra da firewall é aplicada, removida ou modificada.",
        ],
    }
