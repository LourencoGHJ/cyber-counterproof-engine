"""CLI support for conservative packet evaluation against iptables-save snapshots."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cce.models import InputError, load_json
from cce.nftables import write_json_report
from cce.packet import Packet
from cce.report import sha256_file
from cce.rule_evaluator import evaluate_iptables_packet


_REQUIRED_PACKET_FIELDS = {"source_ip", "destination_ip", "protocol"}
_OPTIONAL_PACKET_FIELDS = {
    "source_port",
    "destination_port",
    "input_interface",
    "output_interface",
    "connection_state",
    "tcp_flags",
    "is_non_initial_fragment",
}
_ALLOWED_PACKET_FIELDS = _REQUIRED_PACKET_FIELDS | _OPTIONAL_PACKET_FIELDS
_EXPECTED_VERDICTS = {"ACCEPT", "DROP", "REJECT", "INCONCLUSIVE"}


def _explain_trace_step(step: dict[str, Any]) -> str:
    """Translate a machine-readable trace reason into a concise explanation."""
    reason = step["reason"]
    action = step.get("action")

    explanations = {
        "protocol_mismatch": "O protocolo do pacote não corresponde ao protocolo exigido pela regra.",
        "source_mismatch": "O endereço de origem do pacote não corresponde à rede definida na regra.",
        "destination_mismatch": "O endereço de destino do pacote não corresponde à rede definida na regra.",
        "input_interface_mismatch": "A interface de entrada do pacote não corresponde à interface exigida.",
        "output_interface_mismatch": "A interface de saída do pacote não corresponde à interface exigida.",
        "source_ports_mismatch": "A porta de origem do pacote não corresponde aos intervalos definidos na regra.",
        "destination_ports_mismatch": "A porta de destino do pacote não corresponde aos intervalos definidos na regra.",
        "either_ports_mismatch": "Nenhuma das portas do pacote corresponde aos intervalos definidos na regra.",
        "connection_state_mismatch": "O estado da ligação não pertence aos estados exigidos pela regra.",
        "fragment_mismatch": "A condição de fragmentação da regra não corresponde ao pacote.",
        "tcp_flags_mismatch": "As flags TCP disponíveis não correspondem à condição da regra.",
        "tcp_flags_mask_mismatch": (
            "As flags TCP selecionadas pela máscara não correspondem às flags "
            "que a regra exige."
        ),
        "tcp_flags_unavailable": (
            "Não foram fornecidos metadados suficientes para avaliar as flags TCP."
        ),
        "all_supported_conditions_match": "Todas as condições reconhecidas desta regra correspondem ao pacote.",
        "terminal_verdict": f"A regra correspondeu e aplicou a decisão terminal {action}.",
        "chain_transfer": f"A regra correspondeu e transferiu a avaliação através de {action}.",
        "return_to_caller": "A regra correspondeu e devolveu a avaliação à cadeia chamadora.",
        "rule_contains_unsupported_or_ambiguous_conditions": (
            "A regra contém condições não suportadas ou ambíguas; não é seguro assumir uma correspondência."
        ),
        "unsupported_or_missing_chain_target": "O destino da regra não pode ser interpretado com segurança.",
        "unsupported_chain_transfer_operation": "A operação de transferência de cadeia não é suportada.",
        "missing_target": "A regra correspondente não contém um destino interpretável.",
    }
    return explanations.get(
        reason,
        f"A avaliação desta regra terminou com o motivo técnico: {reason}.",
    )


def _explain_decision(status: str, decision_source: str) -> str:
    """Describe why the evaluator reached its final verdict."""
    if status == "ACCEPT" and decision_source == "base_chain_policy":
        return "Nenhuma regra terminal decidiu antes do fim da cadeia; foi aplicada a política ACCEPT da cadeia base."
    if status == "DROP" and decision_source == "base_chain_policy":
        return "Nenhuma regra aplicável concedeu o tráfego; foi aplicada a política DROP da cadeia base."
    if status == "ACCEPT":
        return "Uma regra correspondente aplicou a decisão terminal ACCEPT."
    if status == "DROP":
        return "Uma regra correspondente aplicou a decisão terminal DROP."
    if status == "REJECT":
        return "Uma regra correspondente aplicou a decisão terminal REJECT."
    return (
        "A decisão não pôde ser determinada com segurança. Pelo menos uma condição, "
        "regra ou estrutura relevante não foi interpretável."
    )


def _result_with_explanations(result: Any) -> dict[str, Any]:
    """Serialize an evaluation and attach human-readable trace explanations."""
    payload = result.to_dict()
    for step in payload["trace"]:
        step["explanation"] = _explain_trace_step(step)
    payload["decision_explanation"] = _explain_decision(
        result.status,
        result.decision_source,
    )
    return payload


def add_packet_evaluation_parser(subparsers: Any) -> None:
    """Register packet evaluation subcommands."""
    parser = subparsers.add_parser(
        "evaluate-packet",
        help="Avaliar um pacote contra um snapshot iptables-save (modo de leitura).",
    )
    parser.add_argument("--snapshot", required=True, help="Snapshot iptables-save.")
    parser.add_argument(
        "--family",
        required=True,
        choices=("ipv4", "ipv6"),
        help="Família de endereços do snapshot e do pacote.",
    )
    parser.add_argument(
        "--hook",
        required=True,
        choices=("INPUT", "OUTPUT", "FORWARD"),
        help="Base chain filter a avaliar.",
    )
    parser.add_argument(
        "--packet",
        required=True,
        help="Ficheiro JSON com os metadados do pacote.",
    )
    parser.add_argument("--output", required=True, help="Relatório JSON de saída.")

    scenarios = subparsers.add_parser(
        "evaluate-scenarios",
        help="Executar um conjunto de cenários sintéticos de avaliação de pacotes.",
    )
    scenarios.add_argument(
        "--manifest",
        required=True,
        help="Manifesto JSON com snapshots, pacotes e decisões esperadas.",
    )
    scenarios.add_argument("--output", required=True, help="Relatório JSON agregado.")


def _load_packet(path: str | Path, family: str) -> Packet:
    """Load and validate packet metadata without retaining it in the report."""
    data = load_json(path)

    missing = sorted(_REQUIRED_PACKET_FIELDS - data.keys())
    unknown = sorted(data.keys() - _ALLOWED_PACKET_FIELDS)
    if missing:
        raise InputError(
            "Campos obrigatórios em falta no pacote: " + ", ".join(missing)
        )
    if unknown:
        raise InputError(
            "Campos não suportados no pacote: " + ", ".join(unknown)
        )

    packet_data = dict(data)
    tcp_flags = packet_data.get("tcp_flags")
    if tcp_flags is not None:
        if not isinstance(tcp_flags, list) or any(
            not isinstance(flag, str) for flag in tcp_flags
        ):
            raise InputError("tcp_flags tem de ser uma lista de texto ou null.")
        packet_data["tcp_flags"] = frozenset(tcp_flags)

    return Packet(family=family, **packet_data)


def _evaluate_files(
    snapshot_path: Path,
    packet_path: Path,
    family: str,
    hook: str,
) -> Any:
    packet = _load_packet(packet_path, family)
    snapshot_text = snapshot_path.read_text(encoding="utf-8")
    return evaluate_iptables_packet(
        snapshot_text=snapshot_text,
        family=family,
        packet=packet,
        hook=hook,
        table="filter",
    )


def _build_input_evidence(snapshot_path: Path, packet_path: Path) -> dict[str, Any]:
    return {
        "snapshot": {
            "path": str(snapshot_path),
            "sha256": sha256_file(snapshot_path),
        },
        "packet_metadata": {
            "path": str(packet_path),
            "sha256": sha256_file(packet_path),
        },
    }


def _write_single_report(
    result: Any,
    snapshot_path: Path,
    packet_path: Path,
    output_path: str,
) -> None:
    report = {
        "schema_version": "1.0",
        "engine": {
            "name": "Cyber Counterproof Engine",
            "version": "0.1.0",
        },
        "operation": "evaluate_packet",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_evidence": _build_input_evidence(snapshot_path, packet_path),
        "result": _result_with_explanations(result),
        "privacy_note": (
            "O relatório não inclui os endereços IP nem os valores do pacote. "
            "Os hashes identificam os ficheiros de entrada, mas não constituem "
            "uma assinatura digital."
        ),
    }
    write_json_report(report, output_path)


def run_packet_evaluation(args: Any) -> int:
    """Run a single offline evaluation and write a privacy-conscious report."""
    try:
        snapshot_path = Path(args.snapshot)
        packet_path = Path(args.packet)
        result = _evaluate_files(
            snapshot_path,
            packet_path,
            args.family,
            args.hook,
        )
        _write_single_report(result, snapshot_path, packet_path, args.output)

    except (InputError, OSError, TypeError, ValueError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    print(
        f"CCE: {result.status} | Hook: {result.hook} | "
        f"Passos avaliados: {result.steps_evaluated}"
    )
    print(
        f"Decisão: {result.status} | Origem: {result.decision_source} | "
        f"Motivo: {result.reason}"
    )
    print(f"Explicação: {_explain_decision(result.status, result.decision_source)}")
    for step in result.to_dict()["trace"]:
        action = f" -> {step['action']}" if step["action"] else ""
        print(
            f"[{step['result'].upper()}] {step['chain']}:{step['line_number']}"
            f"{action} — {_explain_trace_step(step)}"
        )
    print(f"Relatório: {args.output}")

    return 3 if result.status == "INCONCLUSIVE" else 0


def _load_scenario_manifest(path: str | Path) -> tuple[Path, list[dict[str, Any]]]:
    """Validate a manifest and resolve each input path under its directory."""
    manifest_path = Path(path).resolve()
    data = load_json(manifest_path)
    if data.get("schema_version") != "1.0":
        raise InputError("schema_version do manifesto tem de ser '1.0'.")

    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise InputError("scenarios tem de ser uma lista não vazia.")

    base_dir = manifest_path.parent
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for index, item in enumerate(scenarios):
        prefix = f"scenarios[{index}]"
        if not isinstance(item, dict):
            raise InputError(f"{prefix} tem de ser um objeto JSON.")

        required = {"id", "description", "snapshot", "family", "hook", "packet", "expected"}
        if set(item) != required:
            missing = sorted(required - set(item))
            extra = sorted(set(item) - required)
            raise InputError(
                f"{prefix} tem campos inválidos; em falta={missing}, inesperados={extra}."
            )

        scenario_id = item["id"]
        if not isinstance(scenario_id, str) or not scenario_id.strip():
            raise InputError(f"{prefix}.id tem de ser texto não vazio.")
        if scenario_id in seen_ids:
            raise InputError(f"ID de cenário duplicado: {scenario_id}.")
        seen_ids.add(scenario_id)

        if not isinstance(item["description"], str) or not item["description"].strip():
            raise InputError(f"{prefix}.description tem de ser texto não vazio.")
        if item["family"] not in {"ipv4", "ipv6"}:
            raise InputError(f"{prefix}.family tem de ser ipv4 ou ipv6.")
        if item["hook"] not in {"INPUT", "OUTPUT", "FORWARD"}:
            raise InputError(f"{prefix}.hook não é suportado.")
        if item["expected"] not in _EXPECTED_VERDICTS:
            raise InputError(f"{prefix}.expected não é uma decisão suportada.")

        resolved_paths: dict[str, Path] = {}
        for field in ("snapshot", "packet"):
            value = item[field]
            if not isinstance(value, str) or not value.strip():
                raise InputError(f"{prefix}.{field} tem de ser um caminho relativo.")
            relative = Path(value)
            if relative.is_absolute():
                raise InputError(f"{prefix}.{field} tem de ser relativo ao manifesto.")
            resolved = (base_dir / relative).resolve()
            if not resolved.is_relative_to(base_dir):
                raise InputError(f"{prefix}.{field} não pode sair da pasta do manifesto.")
            resolved_paths[field] = resolved

        normalized.append(
            {
                **item,
                "snapshot_path": resolved_paths["snapshot"],
                "packet_path": resolved_paths["packet"],
            }
        )

    return manifest_path, normalized


def run_packet_scenarios(args: Any) -> int:
    """Run all scenarios in a manifest and compare actual with expected verdicts."""
    try:
        manifest_path, scenarios = _load_scenario_manifest(args.manifest)
        results: list[dict[str, Any]] = []

        for scenario in scenarios:
            result = _evaluate_files(
                scenario["snapshot_path"],
                scenario["packet_path"],
                scenario["family"],
                scenario["hook"],
            )
            passed = result.status == scenario["expected"]
            results.append(
                {
                    "id": scenario["id"],
                    "description": scenario["description"],
                    "expected": scenario["expected"],
                    "actual": result.status,
                    "passed": passed,
                    "input_evidence": _build_input_evidence(
                        scenario["snapshot_path"],
                        scenario["packet_path"],
                    ),
                    "result": _result_with_explanations(result),
                }
            )

        passed_count = sum(item["passed"] for item in results)
        summary = {
            "scenarios_total": len(results),
            "scenarios_passed": passed_count,
            "scenarios_failed": len(results) - passed_count,
        }
        report = {
            "schema_version": "1.0",
            "engine": {
                "name": "Cyber Counterproof Engine",
                "version": "0.1.0",
            },
            "operation": "evaluate_scenarios",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "manifest": {
                "path": str(manifest_path),
                "sha256": sha256_file(manifest_path),
            },
            "summary": summary,
            "scenarios": results,
            "privacy_note": (
                "O relatório não inclui os endereços IP nem os valores dos pacotes. "
                "Os hashes identificam os ficheiros de entrada, mas não constituem "
                "uma assinatura digital."
            ),
        }
        write_json_report(report, args.output)

    except (InputError, OSError, TypeError, ValueError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    for item in results:
        marker = "OK" if item["passed"] else "FALHOU"
        print(
            f"[{marker}] {item['id']}: esperado={item['expected']} "
            f"obtido={item['actual']}"
        )
        print(f"  {item['result']['decision_explanation']}")

    print(
        f"CCE: {passed_count}/{len(results)} cenários corretos | "
        f"Relatório: {args.output}"
    )
    return 0 if passed_count == len(results) else 1
