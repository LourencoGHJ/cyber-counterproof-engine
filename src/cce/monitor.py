
"""Monitorização defensiva de políticas JSON, sem alterar a firewall."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cce.drift import compare_policies
from cce.models import load_json, validate_policy


def utc_now() -> str:
    """Devolve a data e hora atual em UTC."""
    return datetime.now(timezone.utc).isoformat()


def check_policies(
    expected_path: str | Path,
    observed_path: str | Path,
) -> dict[str, Any]:
    """Compara duas políticas JSON e devolve um resultado estruturado."""
    expected_file = Path(expected_path)
    observed_file = Path(observed_path)

    try:
        expected = load_json(expected_file)
        observed = load_json(observed_file)

        expected_errors = validate_policy(expected)
        observed_errors = validate_policy(observed)

        if expected_errors or observed_errors:
            return {
                "timestamp_utc": utc_now(),
                "status": "ERROR",
                "error": "Política inválida.",
                "validation_errors": {
                    "expected": expected_errors,
                    "observed": observed_errors,
                },
            }

        result = compare_policies(expected, observed)

        return {
            "timestamp_utc": utc_now(),
            "status": result["status"],
            "expected_policy": str(expected_file),
            "observed_policy": str(observed_file),
            "summary": result["summary"],
            "findings": result["findings"],
            "limitations": result["limitations"],
        }

    except (OSError, ValueError, TypeError) as exc:
        return {
            "timestamp_utc": utc_now(),
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        }


def append_history(
    result: dict[str, Any],
    history_path: str | Path,
) -> None:
    """Acrescenta uma verificação ao histórico JSON sem apagar as anteriores."""
    target = Path(history_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    history: list[dict[str, Any]] = []

    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Não foi possível ler o histórico existente: {target}"
            ) from exc

        if not isinstance(existing, list):
            raise ValueError("O histórico tem de conter uma lista JSON.")

        if not all(isinstance(item, dict) for item in existing):
            raise ValueError("O histórico contém entradas inválidas.")

        history = existing

    history.append(result)

    # Escrita temporária para reduzir o risco de deixar o histórico truncado.
    temporary = target.with_name(target.name + ".tmp")

    try:
        temporary.write_text(
            json.dumps(history, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_monitor(
    expected_path: str | Path,
    observed_path: str | Path,
    history_path: str | Path,
    interval_seconds: float = 60,
    max_checks: int | None = None,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Executa verificações periódicas até ser interrompido ou atingir o limite."""
    if interval_seconds <= 0:
        raise ValueError("O intervalo tem de ser superior a zero.")

    if max_checks is not None and max_checks < 1:
        raise ValueError("max_checks tem de ser pelo menos 1.")

    checks = 0

    while max_checks is None or checks < max_checks:
        result = check_policies(expected_path, observed_path)
        append_history(result, history_path)

        if on_result is not None:
            on_result(result)

        checks += 1

        if max_checks is not None and checks >= max_checks:
            break

        time.sleep(interval_seconds)
