"""Consolidated, offline analysis of iptables-save snapshots.

Combines structural inventory, conservative rule normalization, heuristic SSH
indicators, and supported terminal-rule conflict analysis. It never reads or
modifies the live firewall.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cce.iptables_ir import SCHEMA_VERSION, parse_iptables_rules_ir
from cce.iptables_risk import find_ssh_rule_candidates
from cce.iptables_save import parse_iptables_save
from cce.policy_conflicts import analyze_iptables_rule_conflicts
from cce.iptables_chain_flow import analyze_iptables_chain_flow
from cce.iptables_policy_compare import compare_policy_rules_to_snapshots
from cce.models import validate_policy


ENGINE_NAME = "Cyber Counterproof Engine"
ENGINE_VERSION = "0.1.0"
SUPPORTED_FAMILIES = ("ipv4", "ipv6")


def _unavailable_ir_summary(rules_total: int) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_status": "unavailable",
        "summary": {
            "rules_total": rules_total,
            "rules_fully_interpreted": 0,
            "rules_partially_interpreted": 0,
            "rules_unparsed": rules_total,
            "unsupported_modules_total": None,
            "unsupported_options_total": None,
            "unsupported_targets_total": None,
            "warnings_total": None,
        },
        "reason": (
            "A representação intermédia não pôde ser gerada com segurança "
            "para este snapshot."
        ),
    }


def _build_ir_summary(snapshot_text: str, family: str) -> dict[str, Any]:
    rules = parse_iptables_rules_ir(snapshot_text, family)
    fully = sum(rule.interpretation == "complete" for rule in rules)
    partially = len(rules) - fully
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_status": "completed",
        "summary": {
            "rules_total": len(rules),
            "rules_fully_interpreted": fully,
            "rules_partially_interpreted": partially,
            "rules_unparsed": 0,
            "unsupported_modules_total": sum(
                len(rule.unsupported_modules) for rule in rules
            ),
            "unsupported_options_total": sum(
                len(rule.unsupported_options) for rule in rules
            ),
            "unsupported_targets_total": sum(
                len(rule.unsupported_targets) for rule in rules
            ),
            "warnings_total": sum(len(rule.warnings) for rule in rules),
        },
    }


def _skipped_analysis(reason: str) -> dict[str, Any]:
    return {
        "analysis_status": "skipped",
        "reason": reason,
        "summary": None,
        "findings": [],
    }



def _build_policy_comparison(
    policy: dict[str, Any],
    families: list[dict[str, Any]],
    snapshots: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Compare declared base-chain policies and supported rules per supplied family."""
    base_policy_comparisons: list[dict[str, Any]] = []
    base_fields = (
        ("INPUT", "input_policy"),
        ("OUTPUT", "output_policy"),
        ("FORWARD", "forward_policy"),
    )

    for family_report in families:
        family = family_report["family"]
        structural = family_report["structural_analysis"]
        malformed = structural["summary"]["malformed_lines"] > 0
        chains = structural["chains"]

        for chain_name, policy_field in base_fields:
            if policy_field not in policy:
                continue

            expected = policy[policy_field].upper()
            observed_chain = next(
                (
                    item for item in chains
                    if item["table"] == "filter"
                    and item["name"] == chain_name
                ),
                None,
            )

            if malformed:
                status = "INCONCLUSIVE"
                observed = (
                    observed_chain["policy"] if observed_chain else None
                )
                reason = (
                    "O snapshot contém linhas malformadas; a política base "
                    "não pode ser validada com segurança."
                )
            elif observed_chain is None:
                status = "MISSING"
                observed = None
                reason = (
                    "A chain base esperada não foi declarada no snapshot."
                )
            else:
                observed = observed_chain["policy"].upper()
                if observed == expected:
                    status = "MATCHED"
                    reason = (
                        "A política da chain base corresponde ao valor declarado."
                    )
                else:
                    status = "MISMATCH"
                    reason = (
                        "A política da chain base difere do valor declarado."
                    )

            base_policy_comparisons.append(
                {
                    "family": family,
                    "table": "filter",
                    "chain": chain_name,
                    "policy_field": policy_field,
                    "expected": expected,
                    "observed": observed,
                    "status": status,
                    "reason": reason,
                }
            )

    rule_comparison = compare_policy_rules_to_snapshots(
        policy,
        tuple(
            (family, snapshots[family]["text"])
            for family in SUPPORTED_FAMILIES
            if family in snapshots
        ),
    )
    rule_summary = rule_comparison["summary"]

    base_matches = sum(
        item["status"] == "MATCHED"
        for item in base_policy_comparisons
    )
    base_drifts = sum(
        item["status"] in {"MISSING", "MISMATCH"}
        for item in base_policy_comparisons
    )
    base_inconclusive = sum(
        item["status"] == "INCONCLUSIVE"
        for item in base_policy_comparisons
    )
    semantic_drifts = rule_summary["conclusive_rule_drifts"]
    policy_drifts = base_drifts + semantic_drifts

    findings = [
        {"category": "base_policy", **item}
        for item in base_policy_comparisons
        if item["status"] != "MATCHED"
    ]
    findings.extend(
        {"category": "semantic_rule", **item}
        for item in rule_comparison["findings"]
    )

    malformed_families = [
        item["family"]
        for item in families
        if item["structural_analysis"]["summary"]["malformed_lines"] > 0
    ]

    return {
        "analysis_status": "partial" if malformed_families else "completed",
        "policy_id": policy["policy_id"],
        "status": "DRIFT" if policy_drifts else "INCONCLUSIVE",
        "summary": {
            "families_compared": len(families),
            "families_with_malformed_lines": len(malformed_families),
            "base_policy_comparisons": len(base_policy_comparisons),
            "base_policy_matches": base_matches,
            "base_policy_drifts": base_drifts,
            "base_policy_inconclusive": base_inconclusive,
            "semantic_rule_comparisons": rule_summary[
                "family_rule_comparisons"
            ],
            "semantic_rule_matches": rule_summary["rules_matched"],
            "semantic_rule_drifts": semantic_drifts,
            "semantic_rule_inconclusive": rule_summary[
                "rules_inconclusive"
            ],
            "semantic_rules_not_applicable": rule_summary[
                "rules_not_applicable"
            ],
            "policy_drift_findings": policy_drifts,
            "findings_total": len(findings),
        },
        "base_policy_comparisons": base_policy_comparisons,
        "rule_comparison": rule_comparison,
        "findings": findings,
        "limitations": [
            "As políticas base são comparadas apenas para INPUT, OUTPUT e FORWARD na tabela filter, nas famílias fornecidas.",
            "A comparação de regras cobre apenas chain, action, protocol, source e destination_port.",
            "O campo service da política é descritivo e não é convertido em condições iptables.",
            "Regras parcialmente interpretadas, seletores não modelados e múltiplos candidatos permanecem INCONCLUSIVE.",
            "A comparação é por regra; não agrega regras nem modela ordem first-match, fluxo de user chains, NAT, routing ou alcance real dos pacotes.",
            "Uma correspondência nos campos suportados não prova conformidade integral nem determina o comportamento do kernel.",
            "Uma família não fornecida não é considerada em falta; simplesmente não foi avaliada.",
            "Nenhuma regra da firewall é aplicada, removida ou modificada.",
        ],
        "integrity_note": (
            "A comparação publica identificadores, cadeias, linhas e classificações, "
            "sem reproduzir seletores IP ou portas das regras."
        ),
    }

def _analyse_family(
    family: str,
    snapshot: dict[str, str],
) -> dict[str, Any]:
    snapshot_text = snapshot["text"]
    structural = parse_iptables_save(snapshot_text, family)
    structural_summary = structural["summary"]
    has_malformed_lines = structural_summary["malformed_lines"] > 0

    structural_report = {
        "summary": structural_summary,
        "chains": structural["chains"],
        "chain_edges": structural["chain_edges"],
        "unresolved_targets": structural["unresolved_targets"],
        "chains_without_explicit_path": structural["chains_without_explicit_path"],
        "match_modules": structural["match_modules"],
        "target_counts": structural["target_counts"],
        "protocol_counts": structural["protocol_counts"],
        "option_counts": structural["option_counts"],
        "limitations": structural["limitations"],
    }

    if has_malformed_lines:
        chain_flow_report = _skipped_analysis(
            "O snapshot contém linhas estruturalmente malformadas; a análise de fluxo estrutural foi omitida."
        )
        ir_report = _unavailable_ir_summary(structural_summary["rules_total"])
        skip_reason = (
            "O snapshot contém linhas estruturalmente malformadas; as análises "
            "semânticas foram omitidas para evitar conclusões incompletas."
        )
        risk_report = {
            "analysis_status": "skipped",
            "reason": skip_reason,
            "candidates": [],
        }
        conflict_report = _skipped_analysis(skip_reason)
    else:
        try:
            chain_flow_report = analyze_iptables_chain_flow(
                snapshot_text,
                family,
            )
        except ValueError:
            chain_flow_report = _skipped_analysis(
                "A análise estrutural do fluxo entre chains não pôde ser concluída."
            )

        try:
            ir_report = _build_ir_summary(snapshot_text, family)
        except ValueError:
            ir_report = _unavailable_ir_summary(structural_summary["rules_total"])

        try:
            candidates = find_ssh_rule_candidates(snapshot_text, family)
            risk_report = {
                "analysis_status": "completed",
                "candidates": candidates,
            }
        except ValueError:
            risk_report = {
                "analysis_status": "unavailable",
                "reason": (
                    "A análise heurística SSH não pôde ser concluída "
                    "para este snapshot."
                ),
                "candidates": [],
            }

        try:
            conflicts = analyze_iptables_rule_conflicts(snapshot_text, family)
            conflict_report = {
                "analysis_status": "completed",
                "summary": conflicts["summary"],
                "findings": conflicts["findings"],
                "limitations": conflicts["limitations"],
            }
        except ValueError:
            conflict_report = _skipped_analysis(
                "A análise de conflitos não pôde ser concluída "
                "para este snapshot."
            )

    return {
        "family": family,
        "input_evidence": {
            "path": snapshot["path"],
            "sha256": snapshot["sha256"],
        },
        "structural_analysis": structural_report,
        "rule_ir": ir_report,
        "risk_indicators": risk_report,
        "rule_conflicts": conflict_report,
        "chain_flow": chain_flow_report,
    }


def analyze_firewall_snapshots(
    snapshots: dict[str, dict[str, str]],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Consolidate one or both IPv4/IPv6 iptables-save snapshots.

    Each snapshot entry must contain non-empty 'path', 'sha256' and 'text'
    strings. When a policy is supplied, declared base-chain policies and
    supported rule selectors are compared. A drift is reported, but a clean
    comparison remains INCONCLUSIVE because real traffic behaviour is not proven.
    """
    if policy is not None:
        policy_errors = validate_policy(policy)
        if policy_errors:
            raise ValueError("Política inválida: " + "; ".join(policy_errors))

    if not isinstance(snapshots, dict) or not snapshots:
        raise ValueError(
            "É necessário fornecer pelo menos um snapshot IPv4 ou IPv6."
        )

    if any(not isinstance(family, str) for family in snapshots):
        raise ValueError("As famílias dos snapshots têm de ser texto.")

    unknown_families = set(snapshots) - set(SUPPORTED_FAMILIES)
    if unknown_families:
        raise ValueError(
            "Famílias não suportadas: " + ", ".join(sorted(unknown_families))
        )

    families: list[dict[str, Any]] = []
    for family in SUPPORTED_FAMILIES:
        if family not in snapshots:
            continue

        entry = snapshots[family]
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(field), str) and entry[field].strip()
            for field in ("path", "sha256", "text")
        ):
            raise ValueError(
                f"O snapshot {family} tem de incluir path, sha256 e text não vazios."
            )

        families.append(_analyse_family(family, entry))

    summary = {
        "status": "INCONCLUSIVE",
        "families_analyzed": len(families),
        "families_not_provided": [
            family for family in SUPPORTED_FAMILIES if family not in snapshots
        ],
        "tables_total": 0,
        "chains_total": 0,
        "rules_total": 0,
        "malformed_lines_total": 0,
        "rules_ir_fully_interpreted": 0,
        "rules_ir_partially_interpreted": 0,
        "rules_ir_unparsed": 0,
        "ssh_rule_candidates": 0,
        "rule_conflict_findings": 0,
        "proven_rule_conflict_findings": 0,
        "potential_rule_conflict_findings": 0,
        "chain_flow_findings": 0,
        "potential_chain_cycles": 0,
        "structurally_unreachable_user_chains": 0,
        "unresolved_chain_targets": 0,
        "policy_base_matches": 0,
        "policy_base_drifts": 0,
        "policy_base_inconclusive": 0,
        "policy_rule_matches": 0,
        "policy_rule_drifts": 0,
        "policy_rule_inconclusive": 0,
        "policy_drift_findings": 0,
        "policy_comparison_findings": 0,
    }
    findings: list[dict[str, Any]] = []

    for family_result in families:
        family = family_result["family"]
        structural_summary = family_result["structural_analysis"]["summary"]
        ir_summary = family_result["rule_ir"]["summary"]
        conflict_findings = family_result["rule_conflicts"]["findings"]
        chain_flow = family_result["chain_flow"]
        chain_flow_summary = chain_flow["summary"] if chain_flow["summary"] else {}
        chain_flow_findings = chain_flow["findings"]
        candidates = family_result["risk_indicators"]["candidates"]

        summary["tables_total"] += structural_summary["tables_total"]
        summary["chains_total"] += structural_summary["chains_total"]
        summary["rules_total"] += structural_summary["rules_total"]
        summary["malformed_lines_total"] += structural_summary["malformed_lines"]
        summary["rules_ir_fully_interpreted"] += ir_summary[
            "rules_fully_interpreted"
        ]
        summary["rules_ir_partially_interpreted"] += ir_summary[
            "rules_partially_interpreted"
        ]
        summary["rules_ir_unparsed"] += ir_summary["rules_unparsed"]
        summary["ssh_rule_candidates"] += len(candidates)
        summary["rule_conflict_findings"] += len(conflict_findings)
        summary["chain_flow_findings"] += len(chain_flow_findings)
        summary["potential_chain_cycles"] += chain_flow_summary.get(
            "cyclic_components_total", 0
        )
        summary["structurally_unreachable_user_chains"] += chain_flow_summary.get(
            "structurally_unreachable_user_chains", 0
        )
        summary["unresolved_chain_targets"] += chain_flow_summary.get(
            "unresolved_targets_total", 0
        )

        for finding in conflict_findings:
            certainty = finding.get("certainty")
            if certainty == "proven":
                summary["proven_rule_conflict_findings"] += 1
            elif certainty == "potential":
                summary["potential_rule_conflict_findings"] += 1
            findings.append(
                {"category": "rule_conflict", "family": family, **finding}
            )

        findings.extend(
            {"category": "ssh_rule_candidate", **candidate}
            for candidate in candidates
        )
        findings.extend(
            {"category": "chain_flow", "family": family, **finding}
            for finding in chain_flow_findings
        )

    report = {
        "schema_version": "1.0",
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "operation": "analyze_snapshot",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "INCONCLUSIVE",
        "status_reason": (
            "O inventário estrutural, a IR e os indicadores estáticos não "
            "substituem a comparação com uma política de referência nem "
            "determinam, por si só, o comportamento real do tráfego."
        ),
        "summary": summary,
        "families": families,
        "findings": findings,
        "limitations": [
            "A análise é offline e utiliza exclusivamente os snapshots fornecidos.",
            "Famílias de endereços não fornecidas não foram avaliadas.",
            "A IR só normaliza condições conhecidas; regras parciais não são tratadas como totalmente interpretadas.",
            "A análise de conflitos cobre regras terminais totalmente interpretadas na mesma cadeia da tabela filter.",
            "A análise de fluxo entre chains é estrutural e não avalia a correspondência dos seletores nem prova ciclos executáveis por pacotes.",
            "Indicadores SSH são heurísticos e não provam exposição externa, acessibilidade ou estado do serviço.",
            "Não são simulados NAT, routing, módulos não suportados ou alterações dinâmicas do ruleset.",
            "Nenhuma regra da firewall é aplicada, removida ou modificada.",
        ],
        "privacy_note": (
            "O relatório contém hashes, caminhos, inventário de cadeias, "
            "contagens de módulos/opções e localizações de descobertas. Não "
            "inclui o texto original das regras nem os valores de endereços, "
            "prefixos ou portas das condições; os indicadores SSH identificam "
            "explicitamente a porta canónica 22. Os hashes identificam os "
            "ficheiros, mas não constituem uma assinatura digital."
        ),
    }

    if policy is not None:
        policy_comparison = _build_policy_comparison(
            policy,
            families,
            snapshots,
        )
        policy_summary = policy_comparison["summary"]
        summary["policy_base_matches"] = policy_summary["base_policy_matches"]
        summary["policy_base_drifts"] = policy_summary["base_policy_drifts"]
        summary["policy_base_inconclusive"] = (
            policy_summary["base_policy_inconclusive"]
        )
        summary["policy_rule_matches"] = policy_summary["semantic_rule_matches"]
        summary["policy_rule_drifts"] = policy_summary["semantic_rule_drifts"]
        summary["policy_rule_inconclusive"] = (
            policy_summary["semantic_rule_inconclusive"]
        )
        summary["policy_drift_findings"] = (
            policy_summary["policy_drift_findings"]
        )
        summary["policy_comparison_findings"] = policy_summary["findings_total"]
        findings.extend(
            {"category": "policy_comparison", **finding}
            for finding in policy_comparison["findings"]
        )
        if policy_summary["policy_drift_findings"]:
            report["status"] = "DRIFT"
            report["status_reason"] = (
                "Foram encontradas divergências conclusivas face à política "
                "de referência nos campos suportados."
            )
        else:
            report["status_reason"] = (
                "Não foram encontradas divergências conclusivas nos campos "
                "suportados, mas a análise não prova o comportamento real "
                "do tráfego nem a conformidade integral da firewall."
            )
        report["summary"]["status"] = report["status"]
        report["policy_comparison"] = policy_comparison

    return report
