"""Gera um dashboard HTML local e autocontido a partir do histórico do CCE."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


_STATUS_META = {
    "PASS": ("PASS", "pass", "Verificação concluída sem divergências reportadas."),
    "DRIFT": ("DRIFT", "drift", "Foram identificadas divergências face à política."),
    "ERROR": ("ERROR", "error", "A verificação terminou com erro."),
    "INCONCLUSIVE": (
        "INCONCLUSIVE",
        "inconclusive",
        "A evidência disponível não permite uma conclusão definitiva.",
    ),
    "FAIL": ("FAIL", "fail", "A verificação identificou uma falha."),
}
_STATUS_ORDER = ("PASS", "DRIFT", "INCONCLUSIVE", "ERROR", "FAIL")


def _escape(value: Any) -> str:
    """Escapa texto dinâmico antes de o inserir no HTML."""
    return html.escape(str(value), quote=True)


def _status(value: Any) -> str:
    """Normaliza estados sem permitir que o histórico controle classes CSS."""
    return str(value or "DESCONHECIDO").strip().upper() or "DESCONHECIDO"


def _status_badge(value: Any) -> str:
    status = _status(value)
    label, css_class, _ = _STATUS_META.get(
        status,
        (status, "unknown", "Estado não classificado pelo dashboard."),
    )
    return (
        f'<span class="badge badge-{css_class}">'
        f'<span class="badge-dot" aria-hidden="true"></span>'
        f"{_escape(label)}</span>"
    )


def _count(value: Any, fallback: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(value, 0)
    return max(fallback, 0)


def _entry_findings(entry: dict[str, Any]) -> list[dict[str, Any]]:
    findings = entry.get("findings", [])
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def _entry_finding_count(entry: dict[str, Any]) -> int:
    findings = _entry_findings(entry)
    summary = entry.get("summary")
    if isinstance(summary, dict) and "findings_total" in summary:
        return _count(summary.get("findings_total"), len(findings))
    return len(findings)


def _trend_chart(history: list[dict[str, Any]]) -> str:
    """Cria um gráfico SVG simples, sem dependências ou pedidos externos."""
    series = history[-20:]
    if not series:
        return (
            '<div class="empty-chart">'
            '<span class="empty-icon" aria-hidden="true">⌁</span>'
            "<strong>Sem atividade para apresentar</strong>"
            "<span>As verificações futuras vão aparecer aqui.</span>"
            "</div>"
        )

    values = [_entry_finding_count(item) for item in series]
    max_value = max(values) or 1
    left, right, top, bottom = 34, 706, 18, 166
    width = right - left
    height = bottom - top
    x_step = width / max(len(values) - 1, 1)

    points: list[tuple[float, float, int]] = []
    for index, value in enumerate(values):
        x = left + index * x_step if len(values) > 1 else (left + right) / 2
        y = bottom - (value / max_value) * (height - 14)
        points.append((x, y, value))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in points)
    area = (
        f"{left},{bottom} "
        + polyline
        + f" {right},{bottom}"
    )
    grid = "".join(
        f'<line class="chart-grid" x1="{left}" y1="{top + i * height / 3:.1f}" '
        f'x2="{right}" y2="{top + i * height / 3:.1f}" />'
        for i in range(4)
    )
    circles = "".join(
        f'<circle class="chart-point" cx="{x:.1f}" cy="{y:.1f}" r="4">'
        f"<title>Verificação {index + 1}: {value} descoberta(s)</title></circle>"
        for index, (x, y, value) in enumerate(points)
    )
    first_time = _escape(series[0].get("timestamp_utc", "Início"))
    last_time = _escape(series[-1].get("timestamp_utc", "Mais recente"))

    return (
        '<div class="chart-wrap">'
        '<svg class="trend-chart" viewBox="0 0 740 208" role="img" '
        'aria-labelledby="trend-title trend-desc">'
        '<title id="trend-title">Descobertas por verificação</title>'
        '<desc id="trend-desc">Evolução do número de descobertas nas últimas '
        f"{len(series)} verificações.</desc>"
        f"{grid}"
        f'<polygon class="chart-area" points="{area}" />'
        f'<polyline class="chart-line" points="{polyline}" />'
        f"{circles}"
        "</svg>"
        '<div class="chart-axis"><span>'
        + first_time
        + "</span><span>"
        + last_time
        + "</span></div></div>"
    )


def _status_distribution(history: list[dict[str, Any]]) -> str:
    total = len(history)
    if not total:
        return '<p class="muted">Ainda não existem estados registados.</p>'

    counts: dict[str, int] = {key: 0 for key in _STATUS_ORDER}
    counts["OTHER"] = 0
    for entry in history:
        key = _status(entry.get("status"))
        if key in counts:
            counts[key] += 1
        else:
            counts["OTHER"] += 1

    segments: list[str] = []
    legend: list[str] = []
    colors = {
        "PASS": "pass",
        "DRIFT": "drift",
        "INCONCLUSIVE": "inconclusive",
        "ERROR": "error",
        "FAIL": "fail",
        "OTHER": "unknown",
    }
    labels = {
        "PASS": "Concluídas",
        "DRIFT": "Divergências",
        "INCONCLUSIVE": "Inconclusivas",
        "ERROR": "Erros",
        "FAIL": "Falhas",
        "OTHER": "Outros estados",
    }
    for key in (*_STATUS_ORDER, "OTHER"):
        count = counts[key]
        if not count:
            continue
        percent = count / total * 100
        segments.append(
            f'<span class="distribution-segment segment-{colors[key]}" '
            f'style="width:{percent:.3f}%" title="{_escape(labels[key])}: {count}"></span>'
        )
        legend.append(
            '<div class="legend-row"><span class="legend-label">'
            f'<i class="legend-dot dot-{colors[key]}" aria-hidden="true"></i>'
            f"{_escape(labels[key])}</span>"
            f'<strong>{count}</strong><span class="legend-percent">'
            f"{percent:.0f}%</span></div>"
        )

    return (
        '<div class="distribution-bar" role="img" aria-label="Distribuição '
        "dos estados das verificações\">"
        + "".join(segments)
        + "</div><div class=\"distribution-legend\">"
        + "".join(legend)
        + "</div>"
    )


def _severity_summary(history: list[dict[str, Any]]) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    for entry in history:
        for finding in _entry_findings(entry):
            severity = str(finding.get("severity", "")).strip().lower()
            if severity in counts and severity != "other":
                counts[severity] += 1
            else:
                counts["other"] += 1

    labels = {
        "critical": "Crítica",
        "high": "Alta",
        "medium": "Média",
        "low": "Baixa",
        "other": "Não classificada",
    }
    css = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
        "other": "severity-other",
    }
    rows = []
    for key in ("critical", "high", "medium", "low", "other"):
        rows.append(
            '<div class="severity-row"><span class="severity-label">'
            f'<i class="severity-dot {css[key]}" aria-hidden="true"></i>'
            f"{labels[key]}</span><strong>{counts[key]}</strong></div>"
        )
    return "".join(rows)


def _latest_findings(entry: dict[str, Any]) -> str:
    findings = _entry_findings(entry)
    if not findings:
        error = entry.get("error")
        if error:
            return (
                '<div class="empty-state empty-state-warning">'
                '<span class="empty-icon" aria-hidden="true">!</span>'
                "<div><strong>A verificação não produziu descobertas.</strong>"
                '<p class="muted">'
                + _escape(error)
                + "</p></div></div>"
            )
        return (
            '<div class="empty-state"><span class="empty-icon" aria-hidden="true">✓</span>'
            "<div><strong>Sem descobertas nesta verificação</strong>"
            '<p class="muted">Não foram registadas descobertas para a execução mais recente.</p>'
            "</div></div>"
        )

    rows: list[str] = []
    for finding in findings[:12]:
        severity = str(finding.get("severity", "unknown")).strip().lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "unknown"
        code = finding.get("code", finding.get("id", "SEM-CÓDIGO"))
        rule_id = finding.get("rule_id", finding.get("rule", "—"))
        description = (
            finding.get("title")
            or finding.get("detail")
            or finding.get("message")
            or finding.get("reason")
            or "Sem descrição adicional."
        )
        rows.append(
            '<article class="finding-row">'
            f'<span class="severity-pill severity-pill-{severity}">{_escape(severity.upper())}</span>'
            '<div class="finding-copy"><strong>'
            + _escape(code)
            + '</strong><span class="finding-meta">Regra: '
            + _escape(rule_id)
            + "</span><p>"
            + _escape(description)
            + "</p></div></article>"
        )
    return "".join(rows)


def _activity_rows(history: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for entry in reversed(history[-12:]):
        timestamp = entry.get("timestamp_utc", "Sem data")
        status = _status(entry.get("status"))
        count = _entry_finding_count(entry)
        error = entry.get("error", "")
        rows.append(
            '<tr data-status="'
            + _escape(status)
            + '"><td class="time-cell">'
            + _escape(timestamp)
            + "</td><td>"
            + _status_badge(status)
            + "</td><td><strong>"
            + str(count)
            + "</strong></td><td class=\"activity-note\">"
            + (_escape(error) if error else "—")
            + "</td></tr>"
        )
    if rows:
        return "".join(rows)
    return '<tr><td colspan="4" class="table-empty">Sem verificações registadas.</td></tr>'


def generate_dashboard(
    history_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Gera um dashboard estático, responsivo e sem dependências externas."""
    source = Path(history_path)
    target = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Histórico não encontrado: {source}")

    try:
        history = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            raise ValueError("O histórico não contém JSON válido.") from exc
        raise

    if not isinstance(history, list) or not all(
        isinstance(item, dict) for item in history
    ):
        raise ValueError("O histórico tem de ser uma lista de objetos JSON.")

    total = len(history)
    status_counts = {_status(item.get("status")): 0 for item in history}
    for item in history:
        key = _status(item.get("status"))
        status_counts[key] = status_counts.get(key, 0) + 1

    passed = status_counts.get("PASS", 0)
    drift = status_counts.get("DRIFT", 0)
    errors = status_counts.get("ERROR", 0)
    inconclusive = status_counts.get("INCONCLUSIVE", 0)
    findings_events = sum(_entry_finding_count(item) for item in history)

    latest = history[-1] if history else {}
    latest_status = _status(latest.get("status")) if history else "SEM DADOS"
    latest_label, latest_class, latest_message = _STATUS_META.get(
        latest_status,
        (
            latest_status,
            "unknown",
            "Ainda não existe uma classificação para a última verificação.",
        ),
    )
    if not history:
        latest_message = "Executa uma verificação para começares a construir o histórico."
    latest_timestamp = latest.get("timestamp_utc", "Sem verificações") if history else "Sem verificações"
    latest_findings_count = _entry_finding_count(latest) if history else 0

    chart = _trend_chart(history)
    distribution = _status_distribution(history)
    severity_summary = _severity_summary(history)
    findings = _latest_findings(latest) if history else (
        '<div class="empty-state"><span class="empty-icon" aria-hidden="true">⌁</span>'
        "<div><strong>O dashboard ainda não tem dados</strong>"
        '<p class="muted">Executa <code>cce monitor</code> para começar a registar verificações.</p>'
        "</div></div>"
    )
    activity = _activity_rows(history)

    document = r"""<!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="description" content="Dashboard local de auditoria e monitorização do Cyber Counterproof Engine.">
<title>CCE — Firewall Security Operations</title>
<style>
:root {
  color-scheme: dark;
  --bg: #0a101b;
  --sidebar: #080e18;
  --surface: #111c2b;
  --surface-raised: #152236;
  --surface-soft: #0d1725;
  --border: #24354a;
  --border-soft: rgba(128, 160, 190, .13);
  --text: #e8f0f8;
  --muted: #91a4b9;
  --faint: #62778f;
  --cyan: #4bd4e5;
  --blue: #6b9cff;
  --green: #4bd39b;
  --amber: #f5b85c;
  --red: #fb7185;
  --violet: #ad91f5;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
a { color: inherit; text-decoration: none; }
button, input, select { font: inherit; }
.app { min-height: 100vh; }
.sidebar {
  position: fixed; inset: 0 auto 0 0; width: 238px; z-index: 5;
  display: flex; flex-direction: column; background: var(--sidebar);
  border-right: 1px solid var(--border-soft); padding: 24px 16px 18px;
}
.brand { display: flex; align-items: center; gap: 11px; padding: 0 9px 28px; }
.brand-mark {
  width: 36px; height: 36px; display: grid; place-items: center; border-radius: 11px;
  color: #07131d; font-weight: 900; font-size: 12px; letter-spacing: -.5px;
  background: linear-gradient(145deg, #7ce8ed, #38a9d5);
  box-shadow: 0 5px 22px rgba(58, 196, 220, .16);
}
.brand-name { font-size: 14px; font-weight: 750; letter-spacing: .1px; }
.brand-sub { color: var(--faint); font-size: 10px; letter-spacing: 1.55px; margin-top: 3px; }
.nav-label { color: #647b93; font-size: 9px; letter-spacing: 1.6px; font-weight: 800; padding: 17px 12px 8px; }
.nav-link {
  display: flex; align-items: center; gap: 11px; color: #9aadc1; font-size: 12px;
  padding: 10px 12px; border-radius: 8px; margin: 2px 0; transition: background .15s, color .15s;
}
.nav-link:hover, .nav-link.active { background: #13283a; color: #e7f8fb; }
.nav-link.active { box-shadow: inset 2px 0 var(--cyan); }
.nav-icon { width: 16px; text-align: center; color: var(--cyan); font-size: 14px; }
.sidebar-bottom { margin-top: auto; }
.local-note {
  border: 1px solid var(--border); background: #0d1826; padding: 12px; border-radius: 10px;
  color: var(--muted); font-size: 10px; line-height: 1.55;
}
.local-note strong { color: var(--green); display: block; font-size: 10px; margin-bottom: 4px; }
.main { margin-left: 238px; min-width: 0; }
.topbar {
  min-height: 66px; display: flex; align-items: center; justify-content: space-between;
  padding: 0 34px; border-bottom: 1px solid var(--border-soft); background: rgba(9, 16, 27, .84);
}
.breadcrumb { color: var(--muted); font-size: 11px; }
.breadcrumb strong { color: var(--text); font-weight: 650; }
.top-meta { display: flex; align-items: center; gap: 15px; color: var(--muted); font-size: 10px; }
.live-indicator { display: inline-flex; align-items: center; gap: 7px; }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 10px rgba(75,211,155,.5); }
.content { max-width: 1540px; margin: 0 auto; padding: 30px 34px 40px; }
.page-heading { display: flex; justify-content: space-between; align-items: flex-end; gap: 20px; margin-bottom: 22px; }
.eyebrow { color: var(--cyan); font-size: 9px; font-weight: 800; letter-spacing: 1.8px; text-transform: uppercase; }
h1 { font-size: clamp(23px, 2.2vw, 30px); line-height: 1.15; margin: 8px 0 7px; letter-spacing: -.8px; }
.subtitle { color: var(--muted); font-size: 12px; margin: 0; line-height: 1.6; }
.generated { color: var(--faint); font-size: 10px; text-align: right; }
.hero {
  display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(210px, .8fr); gap: 18px;
  padding: 21px 23px; border: 1px solid #245064; border-radius: 13px; overflow: hidden;
  background: radial-gradient(ellipse at 86% 0%, rgba(57, 177, 199, .11), transparent 43%), #101d2d;
  position: relative; margin-bottom: 18px;
}
.hero:before { content: ""; position: absolute; top: 0; left: 0; bottom: 0; width: 3px; background: var(--cyan); }
.hero-copy { min-width: 0; }
.hero-topline { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.hero-label { color: #8da4b9; font-size: 9px; letter-spacing: 1.3px; font-weight: 800; }
.hero h2 { font-size: 19px; margin: 13px 0 6px; letter-spacing: -.35px; }
.hero p { color: #a7b8c9; font-size: 11px; line-height: 1.65; margin: 0; max-width: 690px; }
.hero-side { border-left: 1px solid var(--border); padding-left: 22px; display: flex; flex-direction: column; justify-content: center; gap: 7px; }
.hero-side .label { color: var(--faint); font-size: 9px; text-transform: uppercase; letter-spacing: 1.1px; }
.hero-side strong { font-size: 22px; font-weight: 750; letter-spacing: -.4px; }
.hero-side span:last-child { color: var(--muted); font-size: 10px; }
.badge {
  display: inline-flex; align-items: center; gap: 6px; width: fit-content; border-radius: 99px;
  padding: 5px 9px; font-size: 9px; font-weight: 850; letter-spacing: .45px;
  border: 1px solid transparent; white-space: nowrap;
}
.badge-dot { width: 6px; height: 6px; display: inline-block; background: currentColor; border-radius: 50%; }
.badge-pass { color: var(--green); background: rgba(75,211,155,.1); border-color: rgba(75,211,155,.2); }
.badge-drift, .badge-fail { color: var(--amber); background: rgba(245,184,92,.1); border-color: rgba(245,184,92,.22); }
.badge-error { color: var(--red); background: rgba(251,113,133,.1); border-color: rgba(251,113,133,.2); }
.badge-inconclusive, .badge-unknown { color: #b4a0fa; background: rgba(173,145,245,.1); border-color: rgba(173,145,245,.2); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 13px; margin-bottom: 18px; }
.metric {
  background: var(--surface); border: 1px solid var(--border-soft); border-radius: 11px; padding: 16px 17px;
  min-height: 104px; position: relative;
}
.metric-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.metric-label { color: var(--muted); font-size: 10px; font-weight: 650; }
.metric-icon {
  width: 27px; height: 27px; border-radius: 8px; display: grid; place-items: center;
  background: #172b3e; color: var(--cyan); font-size: 12px;
}
.metric-value { font-size: 25px; font-weight: 760; letter-spacing: -.8px; margin-top: 10px; }
.metric-foot { color: var(--faint); font-size: 9px; margin-top: 2px; }
.metric-pass .metric-value { color: var(--green); }
.metric-drift .metric-value { color: var(--amber); }
.metric-findings .metric-value { color: var(--cyan); }
.grid-main { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(280px, .85fr); gap: 15px; margin-bottom: 15px; }
.grid-bottom { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); gap: 15px; margin-bottom: 15px; }
.panel {
  background: var(--surface); border: 1px solid var(--border-soft); border-radius: 11px;
  padding: 18px 19px; min-width: 0;
}
.panel-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 15px; margin-bottom: 14px; }
.panel-title { font-size: 12px; font-weight: 750; margin: 0; letter-spacing: -.1px; }
.panel-caption { color: var(--faint); font-size: 9px; margin: 5px 0 0; line-height: 1.5; }
.panel-tag { color: var(--muted); border: 1px solid var(--border); border-radius: 6px; padding: 4px 7px; font-size: 9px; white-space: nowrap; }
.chart-wrap { width: 100%; }
.trend-chart { display: block; width: 100%; height: auto; min-height: 150px; overflow: visible; }
.chart-grid { stroke: rgba(133, 158, 184, .13); stroke-width: 1; stroke-dasharray: 3 5; }
.chart-area { fill: url(#chartFill); opacity: .19; }
.chart-line { fill: none; stroke: var(--cyan); stroke-width: 2.4; stroke-linecap: round; stroke-linejoin: round; }
.chart-point { fill: var(--surface); stroke: var(--cyan); stroke-width: 2; }
.chart-axis { display: flex; justify-content: space-between; gap: 10px; color: var(--faint); font-size: 9px; padding: 1px 4px 0; }
.empty-chart { min-height: 190px; display: flex; flex-direction: column; justify-content: center; align-items: center; gap: 8px; color: var(--muted); font-size: 10px; }
.empty-chart strong { color: var(--text); font-size: 11px; }
.empty-icon { color: var(--cyan); font-size: 22px; line-height: 1; }
.distribution-bar { height: 10px; border-radius: 99px; display: flex; overflow: hidden; background: #1b2b3c; margin: 20px 0 18px; }
.distribution-segment { min-width: 2px; transition: width .2s ease; }
.segment-pass { background: var(--green); }
.segment-drift, .segment-fail { background: var(--amber); }
.segment-inconclusive { background: var(--violet); }
.segment-error { background: var(--red); }
.segment-unknown { background: #7890a8; }
.distribution-legend { display: grid; gap: 11px; }
.legend-row, .severity-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: 12px; font-size: 10px; }
.legend-label, .severity-label { display: flex; align-items: center; gap: 8px; color: var(--muted); }
.legend-row strong, .severity-row strong { font-size: 10px; color: var(--text); }
.legend-percent { color: var(--faint); min-width: 31px; text-align: right; font-size: 9px; }
.legend-dot, .severity-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.dot-pass { background: var(--green); }
.dot-drift, .dot-fail { background: var(--amber); }
.dot-inconclusive { background: var(--violet); }
.dot-error { background: var(--red); }
.dot-unknown { background: #7890a8; }
.grid-bottom .panel { min-height: 240px; }
.findings-list { display: grid; }
.finding-row { display: grid; grid-template-columns: 72px minmax(0,1fr); gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border-soft); }
.finding-row:first-child { padding-top: 3px; }
.finding-row:last-child { border-bottom: 0; padding-bottom: 0; }
.severity-pill { width: fit-content; height: fit-content; padding: 4px 7px; border-radius: 5px; font-size: 8px; font-weight: 850; letter-spacing: .55px; }
.severity-pill-critical { color: #ff9aaa; background: rgba(251,113,133,.14); }
.severity-pill-high { color: #ffc080; background: rgba(245,158,82,.14); }
.severity-pill-medium { color: #f5d17a; background: rgba(245,199,92,.12); }
.severity-pill-low { color: #7bdab4; background: rgba(75,211,155,.12); }
.severity-pill-unknown { color: #a6b8c9; background: rgba(145,164,185,.12); }
.finding-copy { min-width: 0; }
.finding-copy strong { display: block; font-size: 10px; overflow-wrap: anywhere; }
.finding-meta { display: block; color: var(--cyan); font-size: 9px; margin-top: 4px; }
.finding-copy p { color: var(--muted); font-size: 9px; line-height: 1.55; margin: 6px 0 0; overflow-wrap: anywhere; }
.severity-stack { display: grid; gap: 14px; padding: 7px 0; }
.severity-row { grid-template-columns: minmax(0, 1fr) auto; }
.severity-critical { background: var(--red); }
.severity-high { background: #f59e52; }
.severity-medium { background: #e9bf67; }
.severity-low { background: var(--green); }
.severity-other { background: #7890a8; }
.severity-note { margin-top: 17px; border-top: 1px solid var(--border-soft); padding-top: 13px; color: var(--faint); font-size: 9px; line-height: 1.55; }
.empty-state { min-height: 145px; display: flex; align-items: center; gap: 13px; color: var(--text); font-size: 10px; }
.empty-state .empty-icon { width: 34px; height: 34px; display: grid; place-items: center; flex: 0 0 auto; border-radius: 10px; background: rgba(75,211,155,.1); color: var(--green); }
.empty-state strong { font-size: 10px; }
.empty-state p { margin: 5px 0 0; line-height: 1.55; overflow-wrap: anywhere; }
.empty-state-warning .empty-icon { color: var(--amber); background: rgba(245,184,92,.1); }
.activity-panel { padding-bottom: 8px; }
.activity-tools { display: flex; align-items: center; gap: 8px; }
.filter-input, .filter-select {
  color: var(--text); background: #0d1725; border: 1px solid var(--border);
  border-radius: 7px; padding: 7px 9px; outline: none; font-size: 9px; min-height: 31px;
}
.filter-input { width: 185px; }
.filter-input:focus, .filter-select:focus { border-color: var(--cyan); box-shadow: 0 0 0 2px rgba(75,212,229,.1); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 650px; }
th { text-align: left; color: var(--faint); font-size: 8px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; padding: 11px 12px; border-bottom: 1px solid var(--border); }
td { color: var(--muted); font-size: 9px; padding: 12px; border-bottom: 1px solid var(--border-soft); vertical-align: middle; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(95,133,171,.06); }
.time-cell { color: #bdcbd9; white-space: nowrap; }
.activity-note { max-width: 340px; overflow-wrap: anywhere; }
.table-empty { color: var(--faint); text-align: center; padding: 25px; }
.no-results { display: none; color: var(--faint); font-size: 10px; text-align: center; padding: 18px; }
.footer {
  display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px;
  color: var(--faint); border-top: 1px solid var(--border-soft); margin-top: 20px; padding-top: 16px; font-size: 9px;
}
.footer strong { color: var(--muted); font-weight: 650; }
@media (max-width: 1120px) {
  .sidebar { width: 205px; }
  .main { margin-left: 205px; }
  .content { padding: 25px 23px 35px; }
  .topbar { padding: 0 23px; }
  .grid-main { grid-template-columns: minmax(0, 1.3fr) minmax(250px, .9fr); }
}
@media (max-width: 850px) {
  .sidebar { position: static; width: auto; height: auto; padding: 12px 16px; display: block; border-right: 0; border-bottom: 1px solid var(--border-soft); }
  .brand { padding: 0 5px 10px; }
  .nav-label, .sidebar-bottom { display: none; }
  .sidebar nav { display: flex; overflow-x: auto; gap: 4px; }
  .nav-link { white-space: nowrap; margin: 0; padding: 8px 10px; }
  .main { margin-left: 0; }
  .topbar { min-height: 51px; }
  .hero { grid-template-columns: 1fr; }
  .hero-side { border-left: 0; border-top: 1px solid var(--border); padding: 13px 0 0; }
  .grid-main, .grid-bottom { grid-template-columns: 1fr; }
}
@media (max-width: 580px) {
  .topbar { padding: 0 16px; }
  .top-meta .live-indicator { display: none; }
  .content { padding: 22px 14px 28px; }
  .page-heading { align-items: flex-start; flex-direction: column; }
  .generated { text-align: left; }
  .hero { padding: 17px; }
  .metric-grid { grid-template-columns: repeat(2, minmax(0,1fr)); gap: 9px; }
  .metric { min-height: 94px; padding: 13px; }
  .metric-value { font-size: 22px; }
  .panel { padding: 15px 13px; }
  .panel-header { flex-direction: column; }
  .activity-tools { width: 100%; flex-wrap: wrap; }
  .filter-input { flex: 1; min-width: 125px; }
  .filter-select { flex: 0 0 auto; }
  .finding-row { grid-template-columns: 63px minmax(0,1fr); gap: 8px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *:before, *:after { scroll-behavior: auto !important; transition: none !important; }
}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar" aria-label="Navegação principal">
  <a class="brand" href="#overview" aria-label="CCE início">
    <span class="brand-mark">CCE</span>
    <span><span class="brand-name">CYBER COUNTERPROOF</span><span class="brand-sub">SECURITY ENGINE</span></span>
  </a>
  <nav>
    <div class="nav-label">WORKSPACE</div>
    <a class="nav-link active" href="#overview"><span class="nav-icon">⌂</span>Visão geral</a>
    <a class="nav-link" href="#trend"><span class="nav-icon">⌁</span>Atividade</a>
    <a class="nav-link" href="#findings"><span class="nav-icon">◇</span>Descobertas</a>
    <a class="nav-link" href="#history"><span class="nav-icon">▤</span>Histórico</a>
    <div class="nav-label">INFORMAÇÃO</div>
    <a class="nav-link" href="#scope"><span class="nav-icon">ⓘ</span>Âmbito e limites</a>
  </nav>
  <div class="sidebar-bottom">
    <div class="local-note"><strong>● MODO LOCAL / READ-ONLY</strong>Vista gerada a partir de ficheiros de histórico. Não estabelece uma ligação contínua à firewall.</div>
  </div>
</aside>

<div class="main">
<header class="topbar">
  <div class="breadcrumb">CCE <span aria-hidden="true">/</span> <strong>Dashboard</strong></div>
  <div class="top-meta"><span class="live-indicator"><i class="live-dot"></i> HISTÓRICO LOCAL</span><span>FIREWALL SECURITY OPERATIONS</span></div>
</header>

<main class="content" id="overview">
  <div class="page-heading">
    <div><div class="eyebrow">SECURITY OPERATIONS / OVERVIEW</div><h1>Firewall security posture</h1><p class="subtitle">Resumo das verificações de política, divergências e atividade registada pelo CCE.</p></div>
    <div class="generated">ÚLTIMA VERIFICAÇÃO<br><strong>LAST_TIMESTAMP</strong></div>
  </div>

  <section class="hero" aria-labelledby="latest-heading">
    <div class="hero-copy">
      <div class="hero-topline"><span class="hero-label">LATEST ASSESSMENT</span>LAST_BADGE</div>
      <h2 id="latest-heading">LATEST_HEADING</h2>
      <p>LATEST_MESSAGE</p>
    </div>
    <div class="hero-side"><span class="label">Descobertas na última execução</span><strong>LATEST_FINDINGS</strong><span>Registos associados à verificação mais recente</span></div>
  </section>

  <section class="metric-grid" aria-label="Indicadores do histórico">
    <article class="metric"><div class="metric-head"><span class="metric-label">Verificações registadas</span><span class="metric-icon">▤</span></div><div class="metric-value">TOTAL_CHECKS</div><div class="metric-foot">Total de execuções no histórico</div></article>
    <article class="metric metric-pass"><div class="metric-head"><span class="metric-label">Sem divergências</span><span class="metric-icon">✓</span></div><div class="metric-value">PASS_COUNT</div><div class="metric-foot">Execuções com estado PASS</div></article>
    <article class="metric metric-drift"><div class="metric-head"><span class="metric-label">Com divergências</span><span class="metric-icon">△</span></div><div class="metric-value">DRIFT_COUNT</div><div class="metric-foot">Execuções com estado DRIFT</div></article>
    <article class="metric metric-findings"><div class="metric-head"><span class="metric-label">Descobertas registadas</span><span class="metric-icon">◇</span></div><div class="metric-value">FINDINGS_TOTAL</div><div class="metric-foot">Contagem acumulada por execução</div></article>
  </section>

  <div class="grid-main">
    <section class="panel" id="trend">
      <div class="panel-header"><div><h2 class="panel-title">Tendência de descobertas</h2><p class="panel-caption">Número de descobertas por verificação · últimas 20 execuções</p></div><span class="panel-tag">HISTÓRICO</span></div>
      TREND_CHART
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2 class="panel-title">Distribuição de estados</h2><p class="panel-caption">Proporção de resultados no histórico</p></div></div>
      STATUS_DISTRIBUTION
    </section>
  </div>

  <div class="grid-bottom">
    <section class="panel" id="findings">
      <div class="panel-header"><div><h2 class="panel-title">Descobertas mais recentes</h2><p class="panel-caption">Detalhes associados à última verificação</p></div><span class="panel-tag">LATEST RUN</span></div>
      <div class="findings-list">LATEST_FINDINGS_HTML</div>
    </section>
    <section class="panel" id="scope">
      <div class="panel-header"><div><h2 class="panel-title">Severidade registada</h2><p class="panel-caption">Contagem de descobertas por severidade, em todo o histórico</p></div></div>
      <div class="severity-stack">SEVERITY_SUMMARY</div>
      <div class="severity-note">A severidade é apresentada conforme os dados fornecidos pelo motor. O dashboard não reclassifica nem infere a gravidade das descobertas.</div>
    </section>
  </div>

  <section class="panel activity-panel" id="history">
    <div class="panel-header"><div><h2 class="panel-title">Histórico de verificações</h2><p class="panel-caption">Últimas 12 execuções · pesquisa e filtro locais</p></div>
      <div class="activity-tools"><label class="sr-only" for="activity-search">Pesquisar histórico</label><input class="filter-input" id="activity-search" type="search" placeholder="Pesquisar estado ou detalhe…" autocomplete="off"><label class="sr-only" for="activity-status">Filtrar por estado</label><select class="filter-select" id="activity-status"><option value="">Todos os estados</option><option>PASS</option><option>DRIFT</option><option>INCONCLUSIVE</option><option>ERROR</option><option>FAIL</option></select></div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Data / hora UTC</th><th>Estado</th><th>Descobertas</th><th>Nota / erro</th></tr></thead><tbody id="activity-body">ACTIVITY_ROWS</tbody></table><div class="no-results" id="no-results">Nenhuma execução corresponde aos filtros.</div></div>
  </section>

  <footer class="footer"><span><strong>CYBER COUNTERPROOF ENGINE</strong> · Dashboard offline</span><span>Fonte: histórico JSON · Sem ligação externa · Sem alterações à firewall</span></footer>
</main>
</div>
</div>
<script>
(() => {
  "use strict";
  const search = document.getElementById("activity-search");
  const status = document.getElementById("activity-status");
  const body = document.getElementById("activity-body");
  const empty = document.getElementById("no-results");
  if (!search || !status || !body || !empty) return;

  const filterRows = () => {
    const query = search.value.trim().toLocaleLowerCase("pt-PT");
    const selected = status.value;
    let visible = 0;
    for (const row of body.querySelectorAll("tr[data-status]")) {
      const matchesText = row.innerText.toLocaleLowerCase("pt-PT").includes(query);
      const matchesStatus = !selected || row.dataset.status === selected;
      const show = matchesText && matchesStatus;
      row.hidden = !show;
      if (show) visible += 1;
    }
    empty.style.display = visible ? "none" : "block";
  };
  search.addEventListener("input", filterRows);
  status.addEventListener("change", filterRows);
})();
</script>
</body>
</html>
"""

    replacements = {
        "LAST_TIMESTAMP": _escape(latest_timestamp),
        "LAST_BADGE": _status_badge(latest_status),
        "LATEST_HEADING": (
            "Sem verificações registadas" if not history else
            ("Avaliação sem divergências" if latest_status == "PASS" else
             "Divergências detetadas" if latest_status == "DRIFT" else
             "Verificação com erro" if latest_status == "ERROR" else
             "Avaliação inconclusiva" if latest_status == "INCONCLUSIVE" else
             "Resultado da última verificação")
        ),
        "LATEST_MESSAGE": _escape(latest_message),
        "LATEST_FINDINGS": str(latest_findings_count),
        "TOTAL_CHECKS": str(total),
        "PASS_COUNT": str(passed),
        "DRIFT_COUNT": str(drift),
        "FINDINGS_TOTAL": str(findings_events),
        "TREND_CHART": chart,
        "STATUS_DISTRIBUTION": distribution,
        "LATEST_FINDINGS_HTML": findings,
        "SEVERITY_SUMMARY": severity_summary,
        "ACTIVITY_ROWS": activity,
    }
    for marker, value in replacements.items():
        document = document.replace(marker, value)

    # SVG fill is declared separately so the generated chart remains self-contained.
    document = document.replace(
        '<svg class="trend-chart"',
        '<svg class="trend-chart"',
    )
    document = document.replace(
        "</style>",
        ".sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }\n"
        "svg .chart-area { fill: rgba(75,212,229,.16); }\n"
        "</style>",
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return target
