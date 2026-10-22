"""CLI do Cyber Counterproof Engine."""
from __future__ import annotations
from cce.drift import compare_policies
from cce.report import build_report, write_report, sha256_file

import argparse
import sys

from cce.engine import analyze
from cce.models import InputError, load_json, validate_policy, validate_requirements
from cce.nftables import (
    NftablesError,
    inspect_live_ruleset,
    validate_rules_file,
    write_json_report,
)




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

    # Novo comando: comparação de políticas
    compare = subs.add_parser(
        "compare-policy",
        help="Comparar política esperada com política observada.",
    )
    compare.add_argument("--expected", required=True)
    compare.add_argument("--observed", required=True)
    compare.add_argument("--output", required=True)

    return parser



def main():
    args = make_parser().parse_args()

    try:
        if args.command == "audit":
            policy = load_json(args.policy)
            reqs = load_json(args.requirements)
            errors = validate_policy(policy) + validate_requirements(reqs)

            if errors:
                for error in errors:
                    print(f"ERRO DE ENTRADA: {error}", file=sys.stderr)
                return 2

            result = analyze(policy, reqs)
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


        if args.command == "compare-policy":
            expected = load_json(args.expected)
            observed = load_json(args.observed)

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

            print(
                f"CCE: {result['status']} | "
                f"Regras esperadas: {result['summary']['expected_rules']} | "
                f"Regras observadas: {result['summary']['observed_rules']} | "
                f"Divergências: {result['summary']['findings_total']}"
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
            print(f"SHA-256: {result['sha256']} | Relatório: {args.output}")
            return 0

    except (InputError, NftablesError, OSError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
