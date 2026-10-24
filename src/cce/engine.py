"""Motor de análise defensiva sobre um modelo simplificado de firewall.

Nota: isto não implementa o motor Netfilter/nftables. A decisão de tráfego é
deliberadamente limitada a regras de exemplo e serve para testar a lógica do CCE.
"""
from __future__ import annotations

import ipaddress
from typing import Any


def _finding(code: str, severity: str, title: str, detail: str, source: str) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "detail": detail,
        "source": source,
    }


def _source_is_global(source: Any) -> bool:
    if source == "any":
        return True
    try:
        return ipaddress.ip_network(source, strict=False).prefixlen == 0
    except (ValueError, TypeError):
        return False


def analyze(policy: dict[str, Any], requirements: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    tests: list[dict[str, Any]] = []
    rules = policy.get("rules", [])
    rule_by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}

    for req in requirements.get("requirements", []):
        req_type = req.get("type")
        severity = req.get("severity", "medium")
        if req_type == "default_input_policy":
            actual = policy.get("input_policy")
            passed = actual == req.get("expected")
            if not passed:
                findings.append(_finding(
                    "CCE-INPUT-DEFAULT-PERMIT", severity,
                    "Política de entrada não é restritiva por omissão",
                    f"Esperado {req.get('expected')!r}; encontrado {actual!r}.",
                    req.get("id", "requirements")
                ))
            tests.append({"id": req.get("id"), "passed": passed, "expected": req.get("expected"), "actual": actual})
        elif req_type == "service_not_globally_exposed":
            service = req.get("service")
            exposed = [
                r for r in rules
                if isinstance(r, dict)
                and r.get("chain") == "input"
                and r.get("action") == "accept"
                and r.get("service") == service
                and _source_is_global(r.get("source", "any"))
            ]
            passed = not exposed
            if not passed:
                findings.append(_finding(
                    "CCE-SERVICE-GLOBAL-EXPOSURE", severity,
                    f"Serviço {service} exposto a qualquer origem",
                    "Existe uma regra de entrada que aceita este serviço a partir de qualquer origem.",
                    req.get("id", "requirements")
                ))
            tests.append({"id": req.get("id"), "passed": passed, "expected": "not globally exposed",
                          "actual": "globally exposed" if exposed else "not globally exposed"})
        elif req_type == "required_rule":
            rule = rule_by_id.get(req.get("rule_id"))
            passed = bool(rule and rule.get("action") == req.get("expected_action"))
            if not passed:
                findings.append(_finding(
                    "CCE-REQUIRED-RULE-MISSING", severity,
                    f"Regra obrigatória ausente ou incorreta: {req.get('rule_id')}",
                    f"A ação esperada era {req.get('expected_action')!r}.",
                    req.get("id", "requirements")
                ))
            tests.append({"id": req.get("id"), "passed": passed,
                          "expected": req.get("expected_action"),
                          "actual": rule.get("action") if rule else None})
        else:
            tests.append({"id": req.get("id", "unknown"), "passed": False,
                          "expected": "known requirement type", "actual": req_type})
            findings.append(_finding(
                "CCE-UNKNOWN-REQUIREMENT", "medium", "Tipo de requisito desconhecido",
                f"O motor ainda não implementa o tipo {req_type!r}.",
                req.get("id", "requirements")
            ))

    for traffic_test in requirements.get("traffic_tests", []):
        actual = evaluate_traffic(policy, traffic_test)
        expected = traffic_test.get("expected")
        passed = actual == expected
        tests.append({
            "id": traffic_test.get("id", "unnamed-traffic-test"),
            "passed": passed,
            "expected": expected,
            "actual": actual,
            "kind": "modelled_traffic"
        })
        if not passed:
            findings.append(_finding(
                "CCE-TRAFFIC-TEST-FAILED", "high",
                f"Teste de tráfego falhou: {traffic_test.get('id')}",
                f"Esperado {expected!r}; o modelo devolveu {actual!r}.",
                traffic_test.get("id", "traffic_tests")
            ))

    passed_count = sum(1 for test in tests if test.get("passed"))
    return {
        "policy_id": policy.get("policy_id", "unknown"),
        "status": "PASS" if not any(f["severity"] in {"high", "critical"} for f in findings) else "FAIL",
        "summary": {
            "tests_total": len(tests),
            "tests_passed": passed_count,
            "tests_failed": len(tests) - passed_count,
            "findings_total": len(findings),
        },
        "findings": findings,
        "tests": tests,
        "limitations": [
            "A avaliação de tráfego é um modelo simplificado, não o Netfilter real.",
            "Não foi aplicada nem inspecionada qualquer configuração do sistema operativo.",
            "PASS significa apenas que os controlos implementados passaram."
        ]
    }


def evaluate_traffic(policy: dict[str, Any], test: dict[str, Any]) -> str:
    """Avalia um cenário no modelo simplificado de regras."""
    try:
        source_ip = ipaddress.ip_address(test["source"])
    except (ValueError, KeyError, TypeError):
        return "error"

    for rule in policy.get("rules", []):
        if not isinstance(rule, dict) or rule.get("chain") != "input":
            continue
        if rule.get("protocol") not in {"any", test.get("protocol")}:
            continue
        if rule.get("destination_port") not in {None, test.get("destination_port")}:
            continue
        if rule.get("service") not in {"any", test.get("service")}:
            continue
        source = rule.get("source", "any")
        if source != "any":
            try:
                if source_ip not in ipaddress.ip_network(source, strict=False):
                    continue
            except ValueError:
                continue
        return rule.get("action", "drop")

    return policy.get("input_policy", "drop")
