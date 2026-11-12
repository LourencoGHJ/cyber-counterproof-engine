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
    }


def analyze_firewall_snapshots(
    snapshots: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Consolidate one or both IPv4/IPv6 iptables-save snapshots.

    Each snapshot entry must contain non-empty 'path', 'sha256' and 'text'
    strings. The overall status is deliberately INCONCLUSIVE because this
    command does not compare a policy baseline or prove real traffic behaviour.
    """
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
    }
    findings: list[dict[str, Any]] = []

    for family_result in families:
        family = family_result["family"]
        structural_summary = family_result["structural_analysis"]["summary"]
        ir_summary = family_result["rule_ir"]["summary"]
        conflict_findings = family_result["rule_conflicts"]["findings"]
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

    return {
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
