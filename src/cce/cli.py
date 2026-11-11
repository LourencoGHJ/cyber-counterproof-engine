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

    return parser


def main():
    args = make_parser().parse_args()

    try:
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
                f"{summary['rule_risk_candidates']}"
            )
            for candidate in result["rule_risk_candidates"]:
                print(
                    f"[{candidate['severity'].upper()}] "
                    f"{candidate['code']}: possível SSH/TCP/22 "
                    f"na cadeia {candidate['chain']} "
                    f"(linha {candidate['line_number']})"
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
            "compare-policy", "compare-live", "compare-iptables-save", "monitor", "dashboard"
        }:
            raise
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
