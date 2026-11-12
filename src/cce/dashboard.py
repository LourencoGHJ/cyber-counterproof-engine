"""Gera um relatório HTML simples a partir do histórico de monitorização do CCE."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


_STATUS = {
    "PASS": ("PASS", "pass", "Sem divergências reportadas."),
    "DRIFT": ("DRIFT", "drift", "Foram encontradas divergências face à política."),
    "ERROR": ("ERROR", "error", "A execução terminou com erro."),
    "INCONCLUSIVE": (
        "INCONCLUSIVE",
        "inconclusive",
        "A evidência disponível não permite uma conclusão definitiva.",
    ),
    "FAIL": ("FAIL", "error", "A verificação identificou uma falha."),
}


def _escape(value: Any) -> str:
    """Escapa valores provenientes do histórico antes de os inserir no HTML."""
    return html.escape(str(value), quote=True)


def _normalise_status(value: Any) -> str:
    return str(value or "DESCONHECIDO").strip().upper() or "DESCONHECIDO"


def _status_badge(value: Any) -> str:
    status = _normalise_status(value)
    label, css_class, _ = _STATUS.get(
        status,
        (status, "unknown", "Estado não reconhecido."),
    )
    return (
        f'<span class="status status-{css_class}">'
        f"{_escape(label)}</span>"
    )


def _findings(entry: dict[str, Any]) -> list[dict[str, Any]]:
    value = entry.get("findings", [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _finding_count(entry: dict[str, Any]) -> int:
    findings = _findings(entry)
    summary = entry.get("summary")
    if isinstance(summary, dict) and "findings_total" in summary:
        value = summary.get("findings_total")
        if isinstance(value, int) and not isinstance(value, bool):
            return max(value, 0)
    return len(findings)


def _metric(label: str, value: int) -> str:
    return (
        '<div class="metric"><span class="metric-label">'
        + _escape(label)
        + '</span><strong class="metric-value">'
        + str(value)
        + "</strong></div>"
    )


def _render_findings(entry: dict[str, Any]) -> str:
    findings = _findings(entry)
    if not findings:
        error = entry.get("error")
        if error:
            return (
                '<p class="notice notice-error">A execução não produziu descobertas: '
                + _escape(error)
                + "</p>"
            )
        return '<p class="empty">Não foram registadas descobertas nesta execução.</p>'

    rows: list[str] = []
    for finding in findings[:50]:
        severity = str(finding.get("severity", "—")).strip().upper() or "—"
        code = finding.get("code", finding.get("id", finding.get("category", "—")))
        rule = finding.get("rule_id", finding.get("rule", "—"))
        description = (
            finding.get("title")
            or finding.get("detail")
            or finding.get("reason")
            or finding.get("message")
            or "Sem descrição adicional."
        )
        family = finding.get("family")
        line_numbers = finding.get("observed_lines")
        evidence_parts = []
        if family:
            evidence_parts.append(str(family))
        if isinstance(line_numbers, list) and line_numbers:
            evidence_parts.append(
                "linha(s) " + ", ".join(str(line) for line in line_numbers)
            )
        evidence = " · ".join(evidence_parts)

        rows.append(
            "<tr><td>"
            + _escape(severity)
            + "</td><td><code>"
            + _escape(code)
            + "</code></td><td>"
            + _escape(rule)
            + "</td><td>"
            + _escape(description)
            + (
                '<span class="evidence">'
                + _escape(evidence)
                + "</span>"
                if evidence
                else ""
            )
            + "</td></tr>"
        )

    return (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Severidade</th><th>Código</th><th>Regra</th>"
        "<th>Descrição / evidência</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        + (
            '<p class="muted small">A mostrar as primeiras 50 descobertas desta execução.</p>'
            if len(findings) > 50
            else ""
        )
    )


def _render_history(history: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for entry in reversed(history[-25:]):
        status = _normalise_status(entry.get("status"))
        timestamp = entry.get("timestamp_utc", "Sem data")
        count = _finding_count(entry)
        note = entry.get("error", "—")
        rows.append(
            "<tr><td>"
            + _escape(timestamp)
            + "</td><td>"
            + _status_badge(status)
            + "</td><td>"
            + str(count)
            + "</td><td>"
            + _escape(note)
            + "</td></tr>"
        )

    if not rows:
        return '<p class="empty">Ainda não existem verificações no histórico.</p>'

    return (
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Data / hora (UTC)</th><th>Estado</th>"
        "<th>Descobertas</th><th>Nota</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        + (
            '<p class="muted small">A mostrar as últimas 25 execuções.</p>'
            if len(history) > 25
            else ""
        )
    )


def generate_dashboard(
    history_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Gera um HTML estático, responsivo e sem dependências externas."""
    source = Path(history_path)
    target = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Histórico não encontrado: {source}")

    try:
        history = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("O histórico não contém JSON válido.") from exc

    if not isinstance(history, list) or not all(
        isinstance(item, dict) for item in history
    ):
        raise ValueError("O histórico tem de ser uma lista de objetos JSON.")

    total = len(history)
    counts = {
        "PASS": 0,
        "DRIFT": 0,
        "INCONCLUSIVE": 0,
        "ERROR": 0,
        "OTHER": 0,
    }
    for entry in history:
        status = _normalise_status(entry.get("status"))
        if status in counts:
            counts[status] += 1
        else:
            counts["OTHER"] += 1

    total_findings = sum(_finding_count(entry) for entry in history)
    latest = history[-1] if history else {}
    latest_status = _normalise_status(latest.get("status")) if history else "SEM DADOS"
    _, _, latest_description = _STATUS.get(
        latest_status,
        (latest_status, "unknown", "Estado não reconhecido."),
    )
    latest_timestamp = latest.get("timestamp_utc", "Sem data") if history else "Sem verificações"
    latest_count = _finding_count(latest) if history else 0

    metrics = "".join(
        (
            _metric("Verificações", total),
            _metric("PASS", counts["PASS"]),
            _metric("DRIFT", counts["DRIFT"]),
            _metric("INCONCLUSIVE", counts["INCONCLUSIVE"]),
            _metric("ERROR", counts["ERROR"]),
        )
    )

    if history:
        latest_panel = (
            '<div class="latest-status">'
            + _status_badge(latest_status)
            + '<span class="latest-description">'
            + _escape(latest_description)
            + "</span></div>"
            '<p class="muted small">Última execução: '
            + _escape(latest_timestamp)
            + " · "
            + str(latest_count)
            + (" descoberta(s)" if latest_count != 1 else " descoberta")
            + "</p>"
        )
    else:
        latest_panel = (
            '<p class="empty">Ainda não existem verificações. '
            "Executa o comando <code>cce monitor</code> para criar o histórico.</p>"
        )

    findings_html = (
        _render_findings(latest)
        if history
        else '<p class="empty">As descobertas da última execução aparecerão aqui.</p>'
    )
    history_html = _render_history(history)

    document = (
        '<!doctype html>\n'
        '<html lang="pt-PT">\n'
        '<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light">\n'
        '<title>CCE — Histórico de auditorias</title>\n'
        "<style>\n"
        ":root { font-family: Arial, Helvetica, sans-serif; color: #202833; "
        "background: #f3f5f7; }\n"
        "* { box-sizing: border-box; }\n"
        "body { margin: 0; background: #f3f5f7; color: #202833; }\n"
        ".page { max-width: 1120px; margin: 0 auto; padding: 34px 28px 48px; }\n"
        "header { display: flex; align-items: flex-start; justify-content: space-between; "
        "gap: 24px; padding-bottom: 22px; border-bottom: 1px solid #d9dee5; }\n"
        ".brand { font-size: 12px; font-weight: 700; letter-spacing: .7px; color: #263b52; }\n"
        "h1 { margin: 18px 0 6px; font-size: 27px; line-height: 1.2; font-weight: 650; }\n"
        ".intro { margin: 0; color: #5e6977; font-size: 14px; line-height: 1.5; }\n"
        ".mode { color: #586675; font-size: 12px; white-space: nowrap; padding-top: 2px; }\n"
        "section { margin-top: 26px; }\n"
        "h2 { margin: 0 0 13px; font-size: 16px; font-weight: 650; color: #263442; }\n"
        ".latest { background: #fff; border: 1px solid #dce2e8; padding: 17px 19px; border-radius: 5px; }\n"
        ".latest-status { display: flex; align-items: center; flex-wrap: wrap; gap: 11px; }\n"
        ".latest-description { color: #4e5a68; font-size: 13px; }\n"
        ".muted { color: #697583; }\n"
        ".small { font-size: 12px; }\n"
        ".latest p { margin: 10px 0 0; }\n"
        ".metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); "
        "background: #fff; border: 1px solid #dce2e8; border-radius: 5px; }\n"
        ".metric { padding: 15px 17px; border-right: 1px solid #e5e9ed; }\n"
        ".metric:last-child { border-right: 0; }\n"
        ".metric-label { display: block; color: #647180; font-size: 12px; }\n"
        ".metric-value { display: block; margin-top: 8px; color: #202b37; font-size: 23px; font-weight: 650; }\n"
        ".status { display: inline-block; padding: 4px 8px; border-radius: 3px; "
        "font-size: 11px; line-height: 1.2; font-weight: 700; }\n"
        ".status-pass { color: #216342; background: #e8f3ec; }\n"
        ".status-drift { color: #855500; background: #fff2d8; }\n"
        ".status-inconclusive { color: #59468a; background: #f0ecf8; }\n"
        ".status-error { color: #982f35; background: #fbeaec; }\n"
        ".status-unknown { color: #4d5864; background: #edf0f2; }\n"
        ".panel { background: #fff; border: 1px solid #dce2e8; border-radius: 5px; padding: 17px 19px; }\n"
        ".table-wrap { overflow-x: auto; }\n"
        "table { width: 100%; border-collapse: collapse; font-size: 13px; }\n"
        "th { text-align: left; padding: 10px 11px; color: #586675; font-weight: 650; "
        "font-size: 11px; background: #f7f8fa; border-bottom: 1px solid #dce2e8; }\n"
        "td { padding: 11px; vertical-align: top; border-bottom: 1px solid #e8ebef; "
        "color: #354150; line-height: 1.45; }\n"
        "tbody tr:last-child td { border-bottom: 0; }\n"
        "tbody tr:hover { background: #fafbfd; }\n"
        "code { color: #314f70; font-family: Consolas, 'Courier New', monospace; font-size: 12px; }\n"
        ".evidence { display: block; margin-top: 4px; color: #75808c; font-size: 11px; }\n"
        ".empty { margin: 0; padding: 12px 0; color: #687482; font-size: 13px; }\n"
        ".notice { margin: 0; padding: 12px; border-radius: 3px; font-size: 13px; }\n"
        ".notice-error { color: #8c3037; background: #fff1f1; }\n"
        "footer { margin-top: 28px; padding-top: 13px; border-top: 1px solid #d9dee5; "
        "color: #75808c; font-size: 11px; line-height: 1.5; }\n"
        "@media (max-width: 760px) {\n"
        " .page { padding: 23px 15px 32px; }\n"
        " header { flex-direction: column; gap: 10px; }\n"
        " .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n"
        " .metric { border-bottom: 1px solid #e5e9ed; }\n"
        " .metric:nth-child(2n) { border-right: 0; }\n"
        " .metric:last-child { grid-column: 1 / -1; border-bottom: 0; }\n"
        " h1 { font-size: 23px; }\n"
        " .panel { padding: 13px 11px; }\n"
        " table { min-width: 650px; }\n"
        "}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        '<main class="page">\n'
        "<header>\n"
        '<div><div class="brand">CYBER COUNTERPROOF ENGINE</div>'
        "<h1>Histórico de auditorias</h1>"
        '<p class="intro">Resultados das verificações de políticas registadas pelo CCE.</p></div>'
        '<div class="mode">Relatório local · Read-only</div>\n'
        "</header>\n"
        "<section>\n"
        "<h2>Última verificação</h2>\n"
        '<div class="latest">'
        + latest_panel
        + "</div>\n"
        "</section>\n"
        "<section>\n"
        "<h2>Resumo</h2>\n"
        '<div class="metrics">'
        + metrics
        + "</div>\n"
        '<p class="muted small">Descobertas registadas no histórico: '
        + str(total_findings)
        + ". Soma por execução; não representa descobertas únicas.</p>\n"
        "</section>\n"
        "<section>\n"
        "<h2>Descobertas da última execução</h2>\n"
        '<div class="panel">'
        + findings_html
        + "</div>\n"
        "</section>\n"
        "<section>\n"
        "<h2>Execuções recentes</h2>\n"
        '<div class="panel">'
        + history_html
        + "</div>\n"
        "</section>\n"
        "<footer>Gerado localmente a partir do histórico JSON. "
        "Este relatório não apresenta métricas do sistema em tempo real e não altera a firewall.</footer>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return target
