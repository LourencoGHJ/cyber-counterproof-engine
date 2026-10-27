"""Modelos e validação de entrada do CCE."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

VALID_ACTIONS = {"accept", "drop", "reject"}
VALID_CHAINS = {"input", "output", "forward"}
VALID_PROTOCOLS = {"any", "tcp", "udp", "icmp"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_TRAFFIC_RESULTS = VALID_ACTIONS | {"error"}


class InputError(ValueError):
    """Erro de formato ou conteúdo dos ficheiros de entrada."""


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"Não foi possível ler {file_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"JSON inválido em {file_path}, linha {exc.lineno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise InputError(f"O conteúdo de {file_path} tem de ser um objeto JSON.")
    return data


def _non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_port(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 65535
    )


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Valida a estrutura da política sem executar ações no sistema."""
    if not isinstance(policy, dict):
        return ["A política tem de ser um objeto JSON."]

    errors: list[str] = []
    if not _non_empty_text(policy.get("policy_id")):
        errors.append("policy_id é obrigatório e tem de ser texto não vazio.")

    for field in ("input_policy", "output_policy"):
        value = policy.get(field)
        if not isinstance(value, str) or value not in VALID_ACTIONS:
            errors.append(f"{field} tem de ser um de {sorted(VALID_ACTIONS)}.")

    if "forward_policy" in policy:
        value = policy["forward_policy"]
        if not isinstance(value, str) or value not in {"accept", "drop"}:
            errors.append("forward_policy tem de ser 'accept' ou 'drop'.")

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
        if not _non_empty_text(rule_id):
            errors.append(f"{prefix}.id é obrigatório e tem de ser texto não vazio.")
        elif rule_id in seen:
            errors.append(f"ID de regra duplicado: {rule_id}.")
        else:
            seen.add(rule_id)

        chain = rule.get("chain")
        if not isinstance(chain, str) or chain not in VALID_CHAINS:
            errors.append(f"{prefix}.chain tem de ser um de {sorted(VALID_CHAINS)}.")

        action = rule.get("action")
        if not isinstance(action, str) or action not in VALID_ACTIONS:
            errors.append(f"{prefix}.action tem de ser um de {sorted(VALID_ACTIONS)}.")

        protocol = rule.get("protocol")
        if not isinstance(protocol, str) or protocol not in VALID_PROTOCOLS:
            errors.append(
                f"{prefix}.protocol tem de ser um de {sorted(VALID_PROTOCOLS)}."
            )

        port = rule.get("destination_port")
        if port is not None and not _valid_port(port):
            errors.append(
                f"{prefix}.destination_port tem de ser null ou um inteiro "
                "entre 1 e 65535."
            )

        source = rule.get("source", "any")
        if source != "any":
            try:
                if not isinstance(source, str):
                    raise ValueError("a origem tem de ser texto")
                ipaddress.ip_network(source, strict=False)
            except (ValueError, TypeError):
                errors.append(
                    f"{prefix}.source não é 'any' nem uma rede IP válida."
                )

        if not _non_empty_text(rule.get("service")):
            errors.append(f"{prefix}.service tem de ser texto não vazio.")

    return errors


def validate_requirements(requirements: dict[str, Any]) -> list[str]:
    """Valida os controlos e cenários de tráfego antes da auditoria."""
    if not isinstance(requirements, dict):
        return ["Os requisitos têm de ser um objeto JSON."]

    errors: list[str] = []
    controls = requirements.get("requirements")
    if not isinstance(controls, list):
        errors.append("requirements tem de ser uma lista.")
        controls = []

    for index, requirement in enumerate(controls):
        prefix = f"requirements[{index}]"
        if not isinstance(requirement, dict):
            errors.append(f"{prefix} tem de ser um objeto.")
            continue

        if not _non_empty_text(requirement.get("id")):
            errors.append(f"{prefix}.id tem de ser texto não vazio.")

        severity = requirement.get("severity", "medium")
        if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
            errors.append(
                f"{prefix}.severity tem de ser um de {sorted(VALID_SEVERITIES)}."
            )

        requirement_type = requirement.get("type")
        if not _non_empty_text(requirement_type):
            errors.append(f"{prefix}.type tem de ser texto não vazio.")
        elif requirement_type == "default_input_policy":
            expected = requirement.get("expected")
            if not isinstance(expected, str) or expected not in VALID_ACTIONS:
                errors.append(
                    f"{prefix}.expected tem de ser um de {sorted(VALID_ACTIONS)}."
                )
        elif requirement_type == "service_not_globally_exposed":
            if not _non_empty_text(requirement.get("service")):
                errors.append(f"{prefix}.service tem de ser texto não vazio.")
        elif requirement_type == "required_rule":
            if not _non_empty_text(requirement.get("rule_id")):
                errors.append(f"{prefix}.rule_id tem de ser texto não vazio.")
            expected_action = requirement.get("expected_action")
            if (
                not isinstance(expected_action, str)
                or expected_action not in VALID_ACTIONS
            ):
                errors.append(
                    f"{prefix}.expected_action tem de ser um de "
                    f"{sorted(VALID_ACTIONS)}."
                )
        # Tipos ainda não implementados são reportados pelo motor como findings.

    traffic_tests = requirements.get("traffic_tests", [])
    if not isinstance(traffic_tests, list):
        errors.append("traffic_tests tem de ser uma lista.")
        return errors

    for index, traffic_test in enumerate(traffic_tests):
        prefix = f"traffic_tests[{index}]"
        if not isinstance(traffic_test, dict):
            errors.append(f"{prefix} tem de ser um objeto.")
            continue

        if "id" in traffic_test and not _non_empty_text(traffic_test.get("id")):
            errors.append(f"{prefix}.id tem de ser texto não vazio.")

        source = traffic_test.get("source")
        try:
            if not isinstance(source, str):
                raise ValueError("a origem tem de ser um endereço IP em texto")
            ipaddress.ip_address(source)
        except (ValueError, TypeError):
            errors.append(f"{prefix}.source tem de ser um endereço IP válido.")

        port = traffic_test.get("destination_port")
        if port is not None and not _valid_port(port):
            errors.append(
                f"{prefix}.destination_port tem de ser null ou um inteiro "
                "entre 1 e 65535."
            )

        protocol = traffic_test.get("protocol")
        if not isinstance(protocol, str) or protocol not in VALID_PROTOCOLS:
            errors.append(
                f"{prefix}.protocol tem de ser um de {sorted(VALID_PROTOCOLS)}."
            )

        if not _non_empty_text(traffic_test.get("service")):
            errors.append(f"{prefix}.service tem de ser texto não vazio.")

        expected = traffic_test.get("expected")
        if not isinstance(expected, str) or expected not in VALID_TRAFFIC_RESULTS:
            errors.append(
                f"{prefix}.expected tem de ser um de "
                f"{sorted(VALID_TRAFFIC_RESULTS)}."
            )

    return errors
