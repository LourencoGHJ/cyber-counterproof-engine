"""Interface de linha de comandos do CCE."""
from __future__ import annotations

import argparse
import json
import sys

from cce.engine import analyze
from cce.models import InputError, load_json, validate_policy, validate_requirements
from cce.report import build_report, write_report


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cce",
        description="Cyber Counterproof Engine — auditoria defensiva de políticas em modo de laboratório."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="Validar política, executar verificações e gerar relatório.")
    audit.add_argument("--policy", required=True, help="Caminho para a política JSON.")
    audit.add_argument("--requirements", required=True, help="Caminho para os requisitos/testes JSON.")
    audit.add_argument("--output", required=True, help="Destino do relatório JSON.")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    if args.command != "audit":
        return 2
    try:
        policy = load_json(args.policy)
        requirements = load_json(args.requirements)
        policy_errors = validate_policy(policy)
        requirement_errors = validate_requirements(requirements)
        if policy_errors or requirement_errors:
            for error in policy_errors + requirement_errors:
                print(f"ERRO DE ENTRADA: {error}", file=sys.stderr)
            return 2
        result = analyze(policy, requirements)
        report = build_report(result, args.policy, args.requirements)
        write_report(report, args.output)
    except (InputError, OSError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    summary = result["summary"]
    print(f"CCE: {result['status']}")
    print(f"Política: {result['policy_id']}")
    print(f"Testes: {summary['tests_passed']}/{summary['tests_total']} passaram")
    print(f"Descobertas: {summary['findings_total']}")
    print(f"Relatório: {args.output}")
    if result["findings"]:
        for finding in result["findings"]:
            print(f"[{finding['severity'].upper()}] {finding['code']}: {finding['title']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
