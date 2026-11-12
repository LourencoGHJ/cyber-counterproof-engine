"""Gera um relatório HTML local a partir do histórico de monitorização do CCE."""

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


def _metric(label: str, value: int, css_class: str = "") -> str:
    safe_class = css_class if css_class in {"pass", "drift", "error"} else ""
    return (
        '<div class="metric">'
        '<span class="metric-label">'
        + _escape(label)
        + '</span><strong class="metric-value '
        + safe_class
        + '">'
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
    for finding in findings[:100]:
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
        evidence_parts: list[str] = []
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
        '<div class="table-wrap"><table class="findings-table">'
        "<thead><tr><th>Severidade</th><th>Código</th><th>Regra</th>"
        "<th>Descrição / evidência</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        + (
            '<p class="muted small">A mostrar as primeiras 100 descobertas desta execução.</p>'
            if len(findings) > 100
            else ""
        )
    )


def _render_run_details(entry: dict[str, Any]) -> str:
    """Mostra contexto adicional da execução sem assumir campos inexistentes."""
    sections: list[str] = []
    findings = _findings(entry)

    if findings:
        finding_items = []
        for finding in findings[:100]:
            code = finding.get("code", finding.get("id", finding.get("category", "Descoberta")))
            rule = finding.get("rule_id", finding.get("rule", "—"))
            reason = (
                finding.get("reason")
                or finding.get("detail")
                or finding.get("message")
                or finding.get("title")
                or "Sem detalhe adicional."
            )
            finding_items.append(
                "<li><strong>"
                + _escape(code)
                + "</strong> · "
                + _escape(rule)
                + " — "
                + _escape(reason)
                + "</li>"
            )
        sections.append(
            "<h4>Descobertas</h4><ul>"
            + "".join(finding_items)
            + "</ul>"
        )

    for key, label in (
        ("error", "Erro"),
        ("validation_errors", "Erros de validação"),
        ("limitations", "Limitações da análise"),
    ):
        value = entry.get(key)
        if value:
            rendered = (
                json.dumps(value, ensure_ascii=False, indent=2)
                if isinstance(value, (dict, list))
                else str(value)
            )
            sections.append(
                "<h4>"
                + label
                + "</h4><pre>"
                + _escape(rendered)
                + "</pre>"
            )

    for key, label in (
        ("expected_policy", "Política esperada"),
        ("observed_policy", "Política observada"),
    ):
        value = entry.get(key)
        if value:
            sections.append(
                "<p><strong>"
                + label
                + ":</strong> <code>"
                + _escape(value)
                + "</code></p>"
            )

    if not sections:
        return '<p class="empty">Esta execução não contém detalhes adicionais.</p>'
    return '<div class="run-detail-content">' + "".join(sections) + "</div>"


def _render_history(history: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    recent = list(enumerate(history[-100:]))
    recent.reverse()

    for original_index, entry in recent:
        status = _normalise_status(entry.get("status"))
        timestamp = str(entry.get("timestamp_utc", "Sem data"))
        count = _finding_count(entry)
        error = entry.get("error", "")
        note = str(error) if error else "—"
        details = _render_run_details(entry)

        rows.append(
            '<tr class="history-row" data-status="'
            + _escape(status)
            + '" data-timestamp="'
            + _escape(timestamp)
            + '"><td class="timestamp">'
            + _escape(timestamp)
            + "</td><td>"
            + _status_badge(status)
            + "</td><td class=\"number\">"
            + str(count)
            + '</td><td class="note">'
            + _escape(note)
            + '</td><td class="details-cell"><details><summary>Ver detalhes</summary>'
            + details
            + "</details></td></tr>"
        )

    if not rows:
        return (
            '<tr><td colspan="5" class="empty table-empty">'
            "Ainda não existem verificações no histórico.</td></tr>"
        )
    return "".join(rows)


def generate_dashboard(
    history_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Gera um HTML estático, responsivo, pesquisável e sem dependências externas."""
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
    latest_timestamp = (
        latest.get("timestamp_utc", "Sem data") if history else "Sem verificações"
    )
    latest_count = _finding_count(latest) if history else 0

    metrics = "".join(
        (
            _metric("Verificações", total),
            _metric("PASS", counts["PASS"], "pass"),
            _metric("DRIFT", counts["DRIFT"], "drift"),
            _metric("INCONCLUSIVE", counts["INCONCLUSIVE"]),
            _metric("ERROR", counts["ERROR"], "error"),
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
    history_rows = _render_history(history)
    generated_history_count = min(total, 100)

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
        ".page { max-width: 1160px; margin: 0 auto; padding: 30px 28px 42px; }\n"
        "header { display: flex; align-items: flex-start; justify-content: space-between; "
        "gap: 24px; padding-bottom: 20px; border-bottom: 1px solid #d9dee5; }\n"
        "h1 { margin: 0 0 6px; font-size: 26px; line-height: 1.2; font-weight: 650; }\n"
        ".intro { margin: 0; color: #5e6977; font-size: 14px; line-height: 1.5; }\n"
        ".mode { color: #586675; font-size: 12px; white-space: nowrap; padding-top: 4px; }\n"
        "section { margin-top: 25px; }\n"
        "h2 { margin: 0 0 12px; font-size: 16px; font-weight: 650; color: #263442; }\n"
        ".latest { background: #fff; border: 1px solid #dce2e8; padding: 16px 18px; border-radius: 4px; }\n"
        ".latest-status { display: flex; align-items: center; flex-wrap: wrap; gap: 11px; }\n"
        ".latest-description { color: #4e5a68; font-size: 13px; }\n"
        ".muted { color: #697583; }\n"
        ".small { font-size: 12px; }\n"
        ".latest p { margin: 9px 0 0; }\n"
        ".metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); "
        "background: #fff; border: 1px solid #dce2e8; border-radius: 4px; }\n"
        ".metric { padding: 14px 16px; border-right: 1px solid #e5e9ed; }\n"
        ".metric:last-child { border-right: 0; }\n"
        ".metric-label { display: block; color: #647180; font-size: 12px; }\n"
        ".metric-value { display: block; margin-top: 7px; color: #202b37; font-size: 22px; font-weight: 650; }\n"
        ".metric-value.pass { color: #216342; } .metric-value.drift { color: #855500; } "
        ".metric-value.error { color: #982f35; }\n"
        ".status { display: inline-block; padding: 4px 8px; border-radius: 3px; "
        "font-size: 11px; line-height: 1.2; font-weight: 700; white-space: nowrap; }\n"
        ".status-pass { color: #216342; background: #e8f3ec; }\n"
        ".status-drift { color: #855500; background: #fff2d8; }\n"
        ".status-inconclusive { color: #59468a; background: #f0ecf8; }\n"
        ".status-error { color: #982f35; background: #fbeaec; }\n"
        ".status-unknown { color: #4d5864; background: #edf0f2; }\n"
        ".panel { background: #fff; border: 1px solid #dce2e8; border-radius: 4px; padding: 16px 17px; }\n"
        ".toolbar { display: flex; align-items: end; flex-wrap: wrap; gap: 10px; margin-bottom: 13px; }\n"
        ".field { display: grid; gap: 5px; min-width: 180px; }\n"
        ".field label { font-size: 11px; color: #586675; font-weight: 650; }\n"
        "input, select, button { font: inherit; }\n"
        "input[type=search], select { min-height: 35px; border: 1px solid #cbd3dc; border-radius: 4px; "
        "padding: 7px 9px; color: #263442; background: #fff; font-size: 12px; }\n"
        "input[type=search] { min-width: 250px; }\n"
        "input:focus, select:focus, button:focus-visible, summary:focus-visible { "
        "outline: 2px solid #4978a8; outline-offset: 2px; }\n"
        "button { min-height: 35px; border: 1px solid #bfc9d4; border-radius: 4px; padding: 7px 11px; "
        "background: #f7f8fa; color: #344253; font-size: 12px; cursor: pointer; }\n"
        "button:hover { background: #edf1f5; }\n"
        ".toolbar-note { margin-left: auto; color: #697583; font-size: 11px; padding: 8px 0; }\n"
        ".table-wrap { overflow-x: auto; }\n"
        "table { width: 100%; border-collapse: collapse; font-size: 13px; }\n"
        "th { text-align: left; padding: 10px 11px; color: #586675; font-weight: 650; "
        "font-size: 11px; background: #f7f8fa; border-bottom: 1px solid #dce2e8; white-space: nowrap; }\n"
        "td { padding: 10px 11px; vertical-align: top; border-bottom: 1px solid #e8ebef; "
        "color: #354150; line-height: 1.45; }\n"
        "tbody tr:last-child td { border-bottom: 0; }\n"
        "tbody tr:hover { background: #fafbfd; }\n"
        ".timestamp { white-space: nowrap; }\n"
        ".number { text-align: right; font-variant-numeric: tabular-nums; }\n"
        ".note { max-width: 280px; overflow-wrap: anywhere; }\n"
        ".details-cell { min-width: 115px; }\n"
        "details summary { color: #315d83; cursor: pointer; font-size: 12px; white-space: nowrap; }\n"
        ".run-detail-content { min-width: 220px; max-width: 560px; padding: 8px 0; color: #4d5967; "
        "font-size: 12px; white-space: normal; }\n"
        ".run-detail-content h4 { margin: 10px 0 5px; color: #263442; font-size: 12px; }\n"
        ".run-detail-content ul { margin: 5px 0; padding-left: 18px; }\n"
        ".run-detail-content li { margin: 5px 0; }\n"
        ".run-detail-content pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f5f7f9; "
        "border: 1px solid #e4e8ed; border-radius: 3px; padding: 8px; font-size: 11px; }\n"
        "code { color: #314f70; font-family: Consolas, 'Courier New', monospace; font-size: 12px; }\n"
        ".evidence { display: block; margin-top: 4px; color: #75808c; font-size: 11px; }\n"
        ".empty { margin: 0; padding: 12px 0; color: #687482; font-size: 13px; }\n"
        ".table-empty { text-align: center; }\n"
        ".notice { margin: 0; padding: 12px; border-radius: 3px; font-size: 13px; }\n"
        ".notice-error { color: #8c3037; background: #fff1f1; }\n"
        ".results-count { color: #697583; font-size: 11px; margin: 11px 0 0; }\n"
        ".no-results { display: none; color: #697583; font-size: 13px; padding: 16px 4px; }\n"
        "footer { margin-top: 25px; padding-top: 12px; border-top: 1px solid #d9dee5; "
        "color: #75808c; font-size: 11px; line-height: 1.5; }\n"
        "@media (max-width: 760px) {\n"
        " .page { padding: 22px 14px 30px; }\n"
        " header { flex-direction: column; gap: 8px; }\n"
        " h1 { font-size: 23px; }\n"
        " .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n"
        " .metric { border-bottom: 1px solid #e5e9ed; }\n"
        " .metric:nth-child(2n) { border-right: 0; }\n"
        " .metric:last-child { grid-column: 1 / -1; border-bottom: 0; }\n"
        " .toolbar { align-items: stretch; }\n"
        " .field { flex: 1 1 180px; min-width: 0; }\n"
        " input[type=search] { min-width: 0; width: 100%; }\n"
        " .toolbar-note { width: 100%; margin: 0; padding: 0; }\n"
        " .panel { padding: 12px 10px; }\n"
        " table { min-width: 750px; }\n"
        "}\n"
        "@media print {\n"
        " body { background: #fff; color: #000; }\n"
        " .page { max-width: none; padding: 0; }\n"
        " .toolbar, .mode, footer { display: none !important; }\n"
        " .latest, .metrics, .panel { border-color: #bbb; break-inside: avoid; }\n"
        " .status { border: 1px solid #999; background: transparent !important; color: #000 !important; }\n"
        " details:not([open]) > :not(summary) { display: none !important; }\n"
        "}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        '<main class="page">\n'
        "<header>\n"
        '<div><h1>Histórico de auditorias</h1>'
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
        '<div class="panel">\n'
        '<div class="toolbar" role="search" aria-label="Filtrar histórico">'
        '<div class="field"><label for="history-search">Pesquisar</label>'
        '<input id="history-search" type="search" placeholder="Data, regra, código ou erro…" autocomplete="off"></div>'
        '<div class="field"><label for="status-filter">Estado</label>'
        '<select id="status-filter"><option value="">Todos os estados</option>'
        '<option value="PASS">PASS</option><option value="DRIFT">DRIFT</option>'
        '<option value="INCONCLUSIVE">INCONCLUSIVE</option><option value="ERROR">ERROR</option>'
        '<option value="FAIL">FAIL</option><option value="DESCONHECIDO">Outros</option></select></div>'
        '<div class="field"><label for="sort-order">Ordenação</label>'
        '<select id="sort-order"><option value="newest">Mais recentes</option>'
        '<option value="oldest">Mais antigas</option></select></div>'
        '<button type="button" id="clear-filters">Limpar filtros</button>'
        '<button type="button" id="print-report">Imprimir</button>'
        '<span class="toolbar-note" id="results-count" aria-live="polite">'
        + str(generated_history_count)
        + " execuções</span></div>\n"
        '<div class="table-wrap"><table id="history-table">'
        "<thead><tr><th>Data / hora (UTC)</th><th>Estado</th>"
        "<th>Descobertas</th><th>Nota</th><th>Detalhes</th></tr></thead>"
        '<tbody id="history-body">'
        + history_rows
        + "</tbody></table></div>"
        '<p class="no-results" id="no-results" role="status">Não existem execuções que correspondam aos filtros.</p>'
        "</div>\n"
        "</section>\n"
        "<footer>Gerado localmente a partir do histórico JSON. "
        "Este relatório não apresenta métricas do sistema em tempo real e não altera a firewall.</footer>\n"
        "</main>\n"
        "<script>\n"
        "(() => {\n"
        '  const search = document.getElementById("history-search");\n'
        '  const status = document.getElementById("status-filter");\n'
        '  const order = document.getElementById("sort-order");\n'
        '  const clear = document.getElementById("clear-filters");\n'
        '  const print = document.getElementById("print-report");\n'
        '  const body = document.getElementById("history-body");\n'
        '  const counter = document.getElementById("results-count");\n'
        '  const empty = document.getElementById("no-results");\n'
        "  if (!search || !status || !order || !clear || !print || !body || !counter || !empty) return;\n"
        "  const rows = Array.from(body.querySelectorAll('tr.history-row'));\n"
        "  const applyFilters = () => {\n"
        "    const query = search.value.trim().toLocaleLowerCase('pt-PT');\n"
        "    const selectedStatus = status.value;\n"
        "    const visible = rows.filter((row) => {\n"
        "      const textMatch = row.textContent.toLocaleLowerCase('pt-PT').includes(query);\n"
        "      const statusMatch = !selectedStatus || row.dataset.status === selectedStatus;\n"
        "      row.hidden = !(textMatch && statusMatch);\n"
        "      return textMatch && statusMatch;\n"
        "    });\n"
        "    visible.sort((a, b) => {\n"
        "      const left = Date.parse(a.dataset.timestamp);\n"
        "      const right = Date.parse(b.dataset.timestamp);\n"
        "      const comparison = Number.isNaN(left) || Number.isNaN(right)\n"
        "        ? a.dataset.timestamp.localeCompare(b.dataset.timestamp)\n"
        "        : left - right;\n"
        "      return order.value === 'oldest' ? comparison : -comparison;\n"
        "    });\n"
        "    visible.forEach((row) => body.appendChild(row));\n"
        "    rows.filter((row) => !visible.includes(row)).forEach((row) => body.appendChild(row));\n"
        "    counter.textContent = visible.length + ' de ' + rows.length + ' execuções';\n"
        "    empty.style.display = visible.length ? 'none' : 'block';\n"
        "  };\n"
        "  search.addEventListener('input', applyFilters);\n"
        "  status.addEventListener('change', applyFilters);\n"
        "  order.addEventListener('change', applyFilters);\n"
        "  clear.addEventListener('click', () => {\n"
        "    search.value = '';\n"
        "    status.value = '';\n"
        "    order.value = 'newest';\n"
        "    applyFilters();\n"
        "    search.focus();\n"
        "  });\n"
        "  print.addEventListener('click', () => window.print());\n"
        "  applyFilters();\n"
        "})();\n"
        "</script>\n"
        "</body>\n"
        "</html>\n"
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return target
