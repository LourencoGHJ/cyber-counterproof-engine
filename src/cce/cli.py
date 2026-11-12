"""CLI do Cyber Counterproof Engine."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cce.dashboard import generate_dashboard
from cce.drift import compare_policies
from cce.engine import analyze
from cce.live import analyze_live_ruleset
from cce.iptables_save import analyze_iptables_saves
from cce.iptables_risk import find_ssh_rule_candidates
from cce.models import (
    InputError,
    load_json,
    validate_policy,
    validate_requirements,
)
from cce.monitor import run_monitor
from cce.nftables import (
    NftablesError,
    inspect_live_ruleset,
    validate_rules_file,
    write_json_report,
)
from cce.report import build_report, write_report, sha256_file
from cce.packet_cli import (
    add_packet_evaluation_parser,
    run_packet_evaluation,
    run_packet_scenarios,
)
from cce.policy_conflicts import analyze_iptables_rule_conflicts
from cce.iptables_chain_flow import analyze_iptables_chain_flow


def make_parser():
    parser = argparse.ArgumentParser(
        prog="cce",
        description="Auditoria defensiva de políticas de firewall.",
    )
    subs = parser.add_subparsers(dest="command", required=True)

    audit = subs.add_parser("audit", help="Auditoria da política JSON do modelo.")
    audit.add_argument("--policy", required=True)
    audit.add_argument("--requirements", required=True)
    audit.add_argument("--output", required=True)

    check = subs.add_parser(
        "validate-nft",
        help="Validar sintaxe nftables sem aplicar regras.",
    )
    check.add_argument("--file", required=True)
    check.add_argument("--output", required=True)

    live = subs.add_parser(
        "inspect-live",
        help="Ler o ruleset ativo sem o modificar.",
    )
    live.add_argument("--output", required=True)
    live.add_argument(
        "--include-ruleset",
        action="store_true",
        help="Incluir ruleset completo no relatório.",
    )

    compare_iptables = subs.add_parser(
        "compare-iptables-save",
        help="Comparar políticas base com snapshots iptables-save.",
    )
    compare_iptables.add_argument("--policy", required=True)
    compare_iptables.add_argument("--ipv4", required=True)
    compare_iptables.add_argument("--ipv6", required=True)
    compare_iptables.add_argument("--output", required=True)

    compare_live = subs.add_parser(
        "compare-live",
        help="Comparar políticas base com um snapshot nftables (análise parcial).",
    )
    compare_live.add_argument("--policy", required=True)
    compare_live.add_argument("--ruleset", required=True)
    compare_live.add_argument("--output", required=True)

    compare = subs.add_parser(
        "compare-policy",
        help="Comparar política esperada com política observada.",
    )
    compare.add_argument("--expected", required=True)
    compare.add_argument("--observed", required=True)
    compare.add_argument("--output", required=True)

    monitor = subs.add_parser(
        "monitor",
        help="Monitorizar políticas periodicamente em modo de leitura.",
    )
    monitor.add_argument("--expected", required=True)
    monitor.add_argument("--observed", required=True)
    monitor.add_argument(
        "--history",
        default="reports/monitor-history.json",
        help="Caminho do histórico JSON.",
    )
    monitor.add_argument(
        "--interval",
        type=float,
        default=60,
        help="Intervalo entre verificações, em segundos.",
    )
    monitor.add_argument(
        "--checks",
        type=int,
        default=None,
        help="Número de verificações; por omissão, executa continuamente.",
    )

    dashboard = subs.add_parser(
        "dashboard",
        help="Gerar o dashboard HTML a partir do histórico.",
    )
    dashboard.add_argument(
        "--history",
        default="reports/monitor-history.json",
        help="Caminho do histórico JSON.",
    )
    dashboard.add_argument(
        "--output",
        default="reports/dashboard.html",
        help="Caminho do dashboard HTML gerado.",
    )

    add_packet_evaluation_parser(subs)

    snapshot_analysis = subs.add_parser(
        "analyze-snapshot",
        help="Consolidar análise offline de snapshots iptables-save.",
    )
    snapshot_analysis.add_argument(
        "--ipv4",
        help="Snapshot iptables-save IPv4 (opcional se for fornecido IPv6).",
    )
    snapshot_analysis.add_argument(
        "--ipv6",
        help="Snapshot ip6tables-save IPv6 (opcional se for fornecido IPv4).",
    )
    snapshot_analysis.add_argument("--output", required=True)

    chain_flow = subs.add_parser(
        "analyze-chain-flow",
        help="Analisar referências, alcançabilidade estrutural e ciclos entre chains iptables.",
    )
    chain_flow.add_argument("--snapshot", required=True)
    chain_flow.add_argument(
        "--family",
        required=True,
        choices=("ipv4", "ipv6"),
    )
    chain_flow.add_argument("--output", required=True)

    conflicts = subs.add_parser(
        "analyze-rule-conflicts",
        help="Detetar regras redundantes, sombreadas e decisões sobrepostas.",
    )
    conflicts.add_argument("--snapshot", required=True)
    conflicts.add_argument(
        "--family",
        required=True,
        choices=("ipv4", "ipv6"),
    )
    conflicts.add_argument("--output", required=True)

    return parser


def main():
    args = make_parser().parse_args()

    try:
        if args.command == "evaluate-packet":
            return run_packet_evaluation(args)

        if args.command == "evaluate-scenarios":
            return run_packet_scenarios(args)

        if args.command == "analyze-snapshot":
            from cce.snapshot_analysis import analyze_firewall_snapshots

            if not args.ipv4 and not args.ipv6:
                print(
                    "ERRO: fornece pelo menos --ipv4 ou --ipv6.",
                    file=sys.stderr,
                )
                return 2

            snapshots = {}
            for family, argument in (
                ("ipv4", args.ipv4),
                ("ipv6", args.ipv6),
            ):
                if not argument:
                    continue

                snapshot_path = Path(argument)
                snapshots[family] = {
                    "path": str(snapshot_path),
                    "sha256": sha256_file(snapshot_path),
                    "text": snapshot_path.read_text(encoding="utf-8"),
                }

            report = analyze_firewall_snapshots(snapshots)
            write_json_report(report, args.output)
            summary = report["summary"]
            print(
                f"CCE: {report['status']} | "
                f"Famílias: {summary['families_analyzed']} | "
                f"Cadeias: {summary['chains_total']} | "
                f"Regras: {summary['rules_total']} | "
                f"Conflitos: {summary['rule_conflict_findings']} | "
                f"Candidatos SSH: {summary['ssh_rule_candidates']} | "
                f"Ciclos potenciais: {summary['potential_chain_cycles']} | "
                f"Chains sem caminho: {summary['structurally_unreachable_user_chains']}"
            )
            print(f"Relatório: {args.output}")

            if summary["rule_conflict_findings"]:
                return 1
            return 3

        if args.command == "analyze-chain-flow":
            snapshot_path = Path(args.snapshot)
            snapshot_text = snapshot_path.read_text(encoding="utf-8")
            result = analyze_iptables_chain_flow(
                snapshot_text,
                args.family,
            )
            report = {
                "schema_version": "1.0",
                "engine": {
                    "name": "Cyber Counterproof Engine",
                    "version": "0.1.0",
                },
                "operation": "analyze_chain_flow",
                "input_evidence": {
                    "snapshot": {
                        "path": str(snapshot_path),
                        "sha256": sha256_file(snapshot_path),
                    }
                },
                "result": result,
            }
            write_json_report(report, args.output)
            summary = result["summary"]
            print(
                f"CCE: CHAIN_FLOW | Chains: {summary['chains_total']} | "
                f"Reachable: {summary['structurally_reachable_chains_total']} | "
                f"Referências: {summary['chain_references_total']} | "
                f"Ciclos potenciais: {summary['cyclic_components_total']} | "
                f"Chains sem caminho: {summary['structurally_unreachable_user_chains']}"
            )
            print(f"Relatório: {args.output}")
            if result["analysis_status"] == "partial":
                return 3
            return 1 if summary["findings_total"] else 0

        if args.command == "analyze-rule-conflicts":
            snapshot_path = Path(args.snapshot)
            snapshot_text = snapshot_path.read_text(encoding="utf-8")
            result = analyze_iptables_rule_conflicts(
                snapshot_text,
                args.family,
            )
            report = {
                "schema_version": "1.0",
                "engine": {
                    "name": "Cyber Counterproof Engine",
                    "version": "0.1.0",
                },
                "operation": "analyze_rule_conflicts",
                "input_evidence": {
                    "snapshot": {
                        "path": str(snapshot_path),
                        "sha256": sha256_file(snapshot_path),
                    },
                },
                "result": result,
                "privacy_note": (
                    "O relatório não inclui endereços IP, interfaces ou linhas "
                    "originais das regras. O hash identifica o ficheiro de entrada, "
                    "mas não constitui uma assinatura digital."
                ),
            }
            write_json_report(report, args.output)
            summary = result["summary"]
            print(
                f"CCE: {summary['findings_total']} descoberta(s) | "
                f"Duplicadas: {summary['duplicate_rules']} | "
                f"Redundantes: {summary['redundant_rules']} | "
                f"Sombreadas: {summary['shadowed_rules']} | "
                f"Sem correspondência: "
                f"{summary['unmatchable_terminal_rules']} | "
                f"Sobreposições potenciais: "
                f"{summary['potential_verdict_overlaps']} | "
                f"Parciais ignoradas: {summary['partial_rules_skipped']} | "
                f"Não terminais ignoradas: "
                f"{summary['non_terminal_rules_skipped']}"
            )
            for finding in result["findings"]:
                if finding["earlier_line"] is None:
                    location = f"{finding['chain']}:{finding['later_line']}"
                    verdicts = str(finding["later_verdict"])
                else:
                    location = (
                        f"{finding['chain']}:{finding['earlier_line']} -> "
                        f"{finding['later_line']}"
                    )
                    verdicts = (
                        f"{finding['earlier_verdict']} / "
                        f"{finding['later_verdict']}"
                    )
                print(
                    f"[{finding['severity'].upper()}] "
                    f"{finding['id']} {finding['code']} | "
                    f"{location} | {verdicts}"
                )
            print(f"Relatório: {args.output}")
            return 1 if summary["findings_total"] else 0

        if args.command == "audit":
            policy = load_json(args.policy)
            requirements = load_json(args.requirements)
            errors = validate_policy(policy) + validate_requirements(requirements)

            if errors:
                for error in errors:
                    print(f"ERRO DE ENTRADA: {error}", file=sys.stderr)
                return 2

            result = analyze(policy, requirements)
            report = build_report(result, args.policy, args.requirements)
            write_report(report, args.output)

            summary = result["summary"]
            print(
                f"CCE: {result['status']} | "
                f"Testes: {summary['tests_passed']}/"
                f"{summary['tests_total']} | "
                f"Descobertas: {summary['findings_total']}"
            )
            print(f"Relatório: {args.output}")

            for finding in result["findings"]:
                print(
                    f"[{finding['severity'].upper()}] "
                    f"{finding['code']}: {finding['title']}"
                )

            return 0 if result["status"] == "PASS" else 1

        if args.command == "monitor":

            def show_result(result):
                print(
                    f"[{result['timestamp_utc']}] "
                    f"CCE: {result['status']}"
                )

                if "summary" in result:
                    print(
                        "Divergências: "
                        f"{result['summary']['findings_total']}"
                    )

                if "error" in result:
                    print(f"ERRO: {result['error']}", file=sys.stderr)

            run_monitor(
                expected_path=args.expected,
                observed_path=args.observed,
                history_path=args.history,
                interval_seconds=args.interval,
                max_checks=args.checks,
                on_result=show_result,
            )
            return 0

        if args.command == "dashboard":
            output = generate_dashboard(args.history, args.output)
            print(f"Dashboard gerado: {output}")
            return 0

        if args.command == "compare-policy":
            expected = load_json(args.expected)
            observed = load_json(args.observed)

            expected_errors = validate_policy(expected)
            observed_errors = validate_policy(observed)
            if expected_errors or observed_errors:
                for error in expected_errors:
                    print(
                        f"ERRO: Política esperada inválida: {error}",
                        file=sys.stderr,
                    )
                for error in observed_errors:
                    print(
                        f"ERRO: Política observada inválida: {error}",
                        file=sys.stderr,
                    )
                return 2

            result = compare_policies(expected, observed)
            report = {
                "schema_version": "1.0",
                "engine": {
                    "name": "Cyber Counterproof Engine",
                    "version": "0.1.0",
                },
                "input_evidence": {
                    "expected": {
                        "path": args.expected,
                        "sha256": sha256_file(args.expected),
                    },
                    "observed": {
                        "path": args.observed,
                        "sha256": sha256_file(args.observed),
                    },
                },
                "result": result,
                "integrity_note": (
                    "Os hashes identificam os ficheiros de entrada; "
                    "não constituem uma assinatura digital."
                ),
            }

            write_report(report, args.output)
            summary = result["summary"]
            print(
                f"CCE: {result['status']} | "
                f"Regras esperadas: {summary['expected_rules']} | "
                f"Regras observadas: {summary['observed_rules']} | "
                f"Divergências: {summary['findings_total']}"
            )
            print(f"Relatório: {args.output}")

            for finding in result["findings"]:
                print(
                    f"[{finding['severity'].upper()}] "
                    f"{finding['code']}: regra {finding['rule_id']}"
                )

            return 0 if result["status"] == "PASS" else 1

        if args.command == "compare-iptables-save":
            policy = load_json(args.policy)
            errors = validate_policy(policy)

            if errors:
                for error in errors:
                    print(f"ERRO DE ENTRADA: {error}", file=sys.stderr)
                return 2

            ipv4_text = Path(args.ipv4).read_text(encoding="utf-8")
            ipv6_text = Path(args.ipv6).read_text(encoding="utf-8")

            result = analyze_iptables_saves(
                policy,
                ipv4_text,
                ipv6_text,
            )

            candidates = (
                find_ssh_rule_candidates(ipv4_text, "ipv4")
                + find_ssh_rule_candidates(ipv6_text, "ipv6")
            )
            result["rule_risk_candidates"] = candidates
            result["summary"]["rules_scanned_for_risk_patterns"] = (
                result["summary"]["rules_total"]
            )
            result["summary"]["rule_risk_candidates"] = len(candidates)
            result["limitations"].append(
                "A deteção SSH/TCP/22 é heurística; candidatos não provam "
                "acessibilidade externa nem disponibilidade do serviço."
            )

            report = {
                "schema_version": "1.0",
                "engine": {
                    "name": "Cyber Counterproof Engine",
                    "version": "0.1.0",
                },
                "input_evidence": {
                    "policy": {
                        "path": args.policy,
                        "sha256": sha256_file(args.policy),
                    },
                    "ipv4_snapshot": {
                        "path": args.ipv4,
                        "sha256": sha256_file(args.ipv4),
                    },
                    "ipv6_snapshot": {
                        "path": args.ipv6,
                        "sha256": sha256_file(args.ipv6),
                    },
                },
                "result": result,
                "integrity_note": (
                    "Os hashes identificam os ficheiros de entrada; "
                    "não constituem uma assinatura digital."
                ),
            }

            write_json_report(report, args.output)
            summary = result["summary"]

            print(
                f"CCE: {result['status']} | "
                f"Chains: {summary['chains_total']} | "
                f"Regras: {summary['rules_total']} | "
                f"Políticas coincidentes: "
                f"{summary['base_policies_matched']} | "
                f"Divergências: "
                f"{summary['base_policy_mismatches']} | "
                f"Riscos candidatos: "
                f"{summary['rule_risk_candidates']} | "
                f"Regras comparadas: "
                f"{summary['rules_semantically_compared']} | "
                f"Drifts de regras: "
                f"{summary['semantic_rule_drifts']}"
            )
            for candidate in result["rule_risk_candidates"]:
                print(
                    f"[{candidate['severity'].upper()}] "
                    f"{candidate['code']}: possível SSH/TCP/22 "
                    f"na cadeia {candidate['chain']} "
                    f"(linha {candidate['line_number']})"
                )

            for comparison in result["rule_policy_comparison"]["findings"]:
                location = (
                    f"{comparison['family']}/{comparison['chain']}"
                )
                if comparison["observed_lines"]:
                    location += (
                        f":{','.join(map(str, comparison['observed_lines']))}"
                    )
                print(
                    f"[{comparison['status']}] "
                    f"{comparison['rule_id']} ({location}) — "
                    f"{comparison['reason']}"
                )

            print(f"Relatório: {args.output}")

            if result["status"] == "DRIFT":
                return 1
            return 3

        if args.command == "compare-live":
            policy = load_json(args.policy)
            errors = validate_policy(policy)

            if errors:
                for error in errors:
                    print(f"ERRO DE ENTRADA: {error}", file=sys.stderr)
                return 2

            snapshot = load_json(args.ruleset)
            result = analyze_live_ruleset(policy, snapshot)

            report = {
                "schema_version": "1.0",
                "engine": {
                    "name": "Cyber Counterproof Engine",
                    "version": "0.1.0",
                },
                "input_evidence": {
                    "policy": {
                        "path": args.policy,
                        "sha256": sha256_file(args.policy),
                    },
                    "ruleset_snapshot": {
                        "path": args.ruleset,
                        "sha256": sha256_file(args.ruleset),
                    },
                },
                "result": result,
                "integrity_note": (
                    "Os hashes identificam os ficheiros de entrada; "
                    "não constituem uma assinatura digital."
                ),
            }

            write_json_report(report, args.output)
            summary = result["summary"]

            print(
                f"CCE: {result['status']} | "
                f"Base chains: {summary['base_chains']} | "
                f"Divergências de política: "
                f"{summary['base_policy_mismatches']}"
            )
            print(f"Relatório: {args.output}")

            if result["status"] == "DRIFT":
                return 1
            if result["status"] == "INCONCLUSIVE":
                return 3
            return 0

        if args.command == "validate-nft":
            result = validate_rules_file(args.file)
            write_json_report(result, args.output)

            status = result.get("status")
            if status is None:
                valid = result.get("valid")
                if valid is True:
                    status = "PASS"
                elif valid is False:
                    status = "FAIL"
                else:
                    status = "ERROR"

            print(f"Validação nftables: {status}; regras aplicadas: não")
            print(f"Relatório: {args.output}")

            if result.get("stderr"):
                print(result["stderr"], file=sys.stderr)

            if status == "PASS":
                return 0
            if status == "ERROR":
                return 2
            return 1

        if args.command == "inspect-live":
            result = inspect_live_ruleset()

            if not args.include_ruleset:
                result.pop("ruleset", None)
                result["ruleset_included"] = False
            else:
                result["ruleset_included"] = True

            write_json_report(result, args.output)
            print(
                "Ruleset consultado em modo de leitura; "
                "nenhuma regra foi alterada."
            )
            print(
                f"SHA-256: {result['sha256']} | "
                f"Relatório: {args.output}"
            )
            return 0

    except (InputError, NftablesError, OSError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        if args.command not in {
            "compare-policy", "compare-live", "compare-iptables-save",
            "analyze-rule-conflicts", "analyze-snapshot", "analyze-chain-flow", "monitor", "dashboard"
        }:
            raise
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
