
"""Gera um dashboard HTML local a partir do histórico do CCE."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _escape(value: Any) -> str:
    """Escapa valores antes de os inserir no HTML."""
    return html.escape(str(value), quote=True)


def generate_dashboard(
    history_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Gera um dashboard HTML estático a partir do histórico JSON."""
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
    passed = sum(item.get("status") == "PASS" for item in history)
    drift = sum(item.get("status") == "DRIFT" for item in history)
    errors = sum(item.get("status") == "ERROR" for item in history)

    latest = history[-1] if history else {}
    latest_status = latest.get("status", "SEM DADOS")

    rows: list[str] = []

    for item in reversed(history):
        status = _escape(item.get("status", "DESCONHECIDO"))
        timestamp = _escape(item.get("timestamp_utc", "Sem data"))
        summary = item.get("summary", {})
        findings = item.get("findings", [])

        if not isinstance(summary, dict):
            summary = {}
        if not isinstance(findings, list):
            findings = []

        count = summary.get("findings_total", len(findings))
        details: list[str] = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            details.append(
                "<li><strong>"
                + _escape(finding.get("code", "SEM-CÓDIGO"))
                + "</strong> — regra "
                + _escape(finding.get("rule_id", "desconhecida"))
                + " ("
                + _escape(finding.get("severity", "sem severidade"))
                + ")</li>"
            )

        detail_html = (
            "<ul>" + "".join(details) + "</ul>"
            if details
            else "<span class='muted'>Sem divergências detalhadas.</span>"
        )

        rows.append(
            "<tr><td>"
            + timestamp
            + "</td><td><span class='status "
            + status.lower()
            + "'>"
            + status
            + "</span></td><td>"
            + _escape(count)
            + "</td><td>"
            + detail_html
            + "</td></tr>"
        )

    latest_class = _escape(latest_status).lower()
    table_rows = "".join(rows) or (
        "<tr><td colspan='4'>Ainda não existem verificações.</td></tr>"
    )

    document = """<!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CCE — Dashboard de Monitorização</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif; }
body { margin: 0; background: #10151d; color: #e8edf4; }
main { max-width: 1100px; margin: auto; padding: 32px 20px; }
h1 { margin-bottom: 6px; }
.muted { color: #9aa8ba; }
.cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: 14px; margin: 24px 0; }
.card, .panel { background: #1a2330; border: 1px solid #2b394a; border-radius: 12px; padding: 18px; }
.label { color: #aab8c9; font-size: 14px; }
.value { font-size: 28px; font-weight: 700; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 13px; border-bottom: 1px solid #2b394a; }
th { color: #aab8c9; font-size: 13px; }
.wrap { overflow-x: auto; }
.status { display: inline-block; padding: 4px 9px; border-radius: 6px; font-weight: 700; font-size: 12px; }
.pass { background: #123d2b; color: #82e6b0; }
.drift { background: #512c18; color: #ffc18a; }
.error { background: #511f2a; color: #ff9eac; }
ul { padding-left: 18px; }
footer { margin-top: 24px; color: #9aa8ba; font-size: 13px; }
</style>
</head>
<body>
<main>
<h1>Cyber Counterproof Engine</h1>
<p class="muted">Dashboard local de monitorização de políticas</p>
<div class="cards">
<div class="card"><div class="label">Último estado</div>
<div class="value"><span class="status LATEST_CLASS">LATEST_STATUS</span></div></div>
<div class="card"><div class="label">Verificações</div><div class="value">TOTAL</div></div>
<div class="card"><div class="label">PASS</div><div class="value">PASSED</div></div>
<div class="card"><div class="label">DRIFT</div><div class="value">DRIFT_COUNT</div></div>
<div class="card"><div class="label">ERROR</div><div class="value">ERROR_COUNT</div></div>
</div>
<section class="panel">
<h2>Histórico de verificações</h2>
<div class="wrap"><table>
<thead><tr><th>Data/hora UTC</th><th>Estado</th><th>Divergências</th><th>Detalhes</th></tr></thead>
<tbody>TABLE_ROWS</tbody>
</table></div>
</section>
<footer>Dados provenientes do histórico JSON. Este dashboard não inspeciona nem altera diretamente a firewall.</footer>
</main>
</body>
</html>
"""

    replacements = {
        "LATEST_CLASS": latest_class,
        "LATEST_STATUS": _escape(latest_status),
        "TOTAL": str(total),
        "PASSED": str(passed),
        "DRIFT_COUNT": str(drift),
        "ERROR_COUNT": str(errors),
        "TABLE_ROWS": table_rows,
    }

    for marker, value in replacements.items():
        document = document.replace(marker, value)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return target
