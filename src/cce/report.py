"""Geração de relatórios com hashes dos ficheiros de entrada."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_report(
    result: dict[str, Any],
    policy_path: str | Path,
    requirements_path: str | Path,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "engine": {"name": "Cyber Counterproof Engine", "version": "0.1.0"},
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_evidence": {
            "policy": {"path": str(policy_path), "sha256": sha256_file(policy_path)},
            "requirements": {"path": str(requirements_path), "sha256": sha256_file(requirements_path)},
        },
        "result": result,
        "integrity_note": (
            "Os hashes identificam os ficheiros de entrada. Não constituem assinatura "
            "digital, não autenticam o relatório e não provam o estado do sistema real."
        ),
    }


def write_report(report: dict[str, Any], output_path: str | Path) -> None:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
