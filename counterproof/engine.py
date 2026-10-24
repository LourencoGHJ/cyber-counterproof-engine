"""Small, deterministic validator for declarative firewall-policy models."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALID_INPUT_POLICIES = {"drop", "accept"}


def validate_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    """Return invariant violations; an empty list means this model passed."""
    violations: list[dict[str, str]] = []

    if policy.get("input_policy") not in VALID_INPUT_POLICIES:
        violations.append({
            "id": "CP001",
            "severity": "HIGH",
            "message": "A política tem de declarar input_policy como 'drop' ou 'accept'.",
        })
    elif policy["input_policy"] != "drop":
        violations.append({
            "id": "CP002",
            "severity": "HIGH",
            "message": "A política de entrada não é restritiva (input_policy deve ser 'drop').",
        })

    if policy.get("allow_loopback") is not True:
        violations.append({
            "id": "CP003",
            "severity": "MEDIUM",
            "message": "A política não confirma explicitamente a permissão de loopback.",
        })

    if policy.get("allow_established_related") is not True:
        violations.append({
            "id": "CP004",
            "severity": "MEDIUM",
            "message": "A política não confirma tráfego established/related.",
        })

    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        violations.append({
            "id": "CP005",
            "severity": "LOW",
            "message": "O campo 'rules' tem de ser uma lista.",
        })

    return violations


def inspect_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()

    try:
        policy = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "1.0",
            "engine_version": "0.1.0",
            "target": str(path),
            "sha256": digest,
            "status": "ERROR",
            "violations": [{
                "id": "CP000",
                "severity": "HIGH",
                "message": f"JSON inválido: {exc}",
            }],
        }

    if not isinstance(policy, dict):
        violations = [{
            "id": "CP006",
            "severity": "HIGH",
            "message": "A raiz do documento JSON tem de ser um objeto.",
        }]
    else:
        violations = validate_policy(policy)

    return {
        "schema_version": "1.0",
        "engine_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(path),
        "sha256": digest,
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="counterproof",
        description="Valida invariantes de uma política declarativa de firewall.",
    )
    parser.add_argument("check", choices=["check"], help="Validar uma política.")
    parser.add_argument("policy", type=Path, help="Caminho para o ficheiro JSON.")
    parser.add_argument("--report", type=Path, help="Guardar o relatório JSON neste caminho.")
    args = parser.parse_args()

    if not args.policy.is_file():
        parser.error(f"Ficheiro não encontrado: {args.policy}")

    report = inspect_file(args.policy)
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")

    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
