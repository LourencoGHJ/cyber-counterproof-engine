"""CLI do Cyber Counterproof Engine."""
from __future__ import annotations

import argparse
import sys

from cce.dashboard import generate_dashboard
from cce.drift import compare_policies
from cce.engine import analyze
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
        if args.command not in {"compare-policy", "monitor", "dashboard"}:
            raise
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
