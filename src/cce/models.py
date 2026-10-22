"""Modelos e validação de entrada do CCE."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

VALID_ACTIONS = {"accept", "drop", "reject"}
VALID_CHAINS = {"input", "output", "forward"}
VALID_PROTOCOLS = {"any", "tcp", "udp", "icmp"}


class InputError(ValueError):
    """Erro de formato ou conteúdo dos ficheiros de entrada."""


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"Não foi possível ler {file_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"JSON inválido em {file_path}, linha {exc.lineno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise InputError(f"O conteúdo de {file_path} tem de ser um objeto JSON.")
    return data


def validate_policy(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy.get("policy_id"), str) or not policy["policy_id"].strip():
        errors.append("policy_id é obrigatório e tem de ser texto.")
    if policy.get("input_policy") not in VALID_ACTIONS:
        errors.append(f"input_policy tem de ser um de {sorted(VALID_ACTIONS)}.")
    if policy.get("output_policy") not in VALID_ACTIONS:
        errors.append(f"output_policy tem de ser um de {sorted(VALID_ACTIONS)}.")
    rules = policy.get("rules")
    if not isinstance(rules, list):
        errors.append("rules tem de ser uma lista.")
        return errors
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} tem de ser um objeto.")
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"{prefix}.id é obrigatório.")
        elif rule_id in seen:
            errors.append(f"ID de regra duplicado: {rule_id}.")
        else:
            seen.add(rule_id)
        if rule.get("chain") not in VALID_CHAINS:
            errors.append(f"{prefix}.chain tem de ser um de {sorted(VALID_CHAINS)}.")
        if rule.get("action") not in VALID_ACTIONS:
            errors.append(f"{prefix}.action tem de ser um de {sorted(VALID_ACTIONS)}.")
        if rule.get("protocol") not in VALID_PROTOCOLS:
            errors.append(f"{prefix}.protocol tem de ser um de {sorted(VALID_PROTOCOLS)}.")
        port = rule.get("destination_port")
        if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
            errors.append(f"{prefix}.destination_port tem de ser null ou um inteiro entre 1 e 65535.")
        source = rule.get("source", "any")
        if source != "any":
            try:
                ipaddress.ip_network(source, strict=False)
            except (ValueError, TypeError):
                errors.append(f"{prefix}.source não é 'any' nem uma rede IP válida.")
        if not isinstance(rule.get("service"), str):
            errors.append(f"{prefix}.service tem de ser texto.")
    return errors


def validate_requirements(requirements: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(requirements.get("requirements"), list):
        errors.append("requirements tem de ser uma lista.")
    if not isinstance(requirements.get("traffic_tests", []), list):
        errors.append("traffic_tests tem de ser uma lista.")
    return errors
