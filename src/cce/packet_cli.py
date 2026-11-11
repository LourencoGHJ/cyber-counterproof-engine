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


def add_packet_evaluation_parser(subparsers: Any) -> None:
    """Register the evaluate-packet subcommand."""
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


def run_packet_evaluation(args: Any) -> int:
    """Run a single offline evaluation and write a privacy-conscious report."""
    try:
        packet = _load_packet(args.packet, args.family)
        snapshot_path = Path(args.snapshot)
        snapshot_text = snapshot_path.read_text(encoding="utf-8")

        result = evaluate_iptables_packet(
            snapshot_text=snapshot_text,
            family=args.family,
            packet=packet,
            hook=args.hook,
            table="filter",
        )

        report = {
            "schema_version": "1.0",
            "engine": {
                "name": "Cyber Counterproof Engine",
                "version": "0.1.0",
            },
            "operation": "evaluate_packet",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "input_evidence": {
                "snapshot": {
                    "path": str(snapshot_path),
                    "sha256": sha256_file(snapshot_path),
                },
                "packet_metadata": {
                    "path": str(args.packet),
                    "sha256": sha256_file(args.packet),
                },
            },
            "result": result.to_dict(),
            "privacy_note": (
                "O relatório não inclui os endereços IP nem os valores do pacote. "
                "Os hashes identificam os ficheiros de entrada, mas não constituem "
                "uma assinatura digital."
            ),
        }
        write_json_report(report, args.output)

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
    for step in result.trace:
        action = f" -> {step.action}" if step.action else ""
        print(
            f"[{step.result.upper()}] {step.chain}:{step.line_number} "
            f"{step.reason}{action}"
        )
    print(f"Relatório: {args.output}")

    # A conclusive ACCEPT/DROP/REJECT is a successful evaluation. Only an
    # inconclusive analysis returns a distinct non-zero exit code.
    return 3 if result.status == "INCONCLUSIVE" else 0
