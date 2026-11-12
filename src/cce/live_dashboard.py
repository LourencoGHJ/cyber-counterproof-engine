"""Read-only live firewall dashboard served over HTTP with Server-Sent Events."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from cce.live import analyze_live_ruleset
from cce.snapshot_analysis import analyze_firewall_snapshots


MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
DEFAULT_INTERVAL_MS = 1000
DEFAULT_TIMEOUT_SECONDS = 5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_loopback_host(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_server_security(
    host: str,
    username: str,
    password: str | None,
) -> None:
    """Require strong HTTP Basic credentials for non-loopback listeners."""
    if not username or ":" in username or any(char in username for char in "\r\n"):
        raise ValueError("O utilizador HTTP tem um formato inválido.")

    if _is_loopback_host(host):
        return

    if not password or len(password) < 24:
        raise ValueError(
            "Para escutar numa interface de rede, define uma password com "
            "pelo menos 24 caracteres na variável de ambiente configurada. "
            "O acesso remoto deve ainda passar por VPN ou proxy HTTPS."
        )


def _safe_command_error(stderr: str, returncode: int | None = None) -> str:
    lowered = stderr.lower()
    if any(token in lowered for token in ("permission denied", "operation not permitted", "must be root")):
        return "Permissões insuficientes para consultar esta fonte da firewall."
    if returncode is not None:
        return f"O comando terminou com código {returncode}."
    return "Não foi possível executar o comando de recolha."


def _run_read_only_command(
    command_name: str,
    arguments: tuple[str, ...],
    timeout_seconds: float,
) -> tuple[dict[str, Any], str | None]:
    """Runs only fixed read-only firewall listing commands; never invokes a shell."""
    executable = shutil.which(command_name)
    if executable is None:
        return (
            {
                "status": "UNAVAILABLE",
                "message": f"{command_name} não está instalado.",
            },
            None,
        )

    try:
        result = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return (
            {
                "status": "ERROR",
                "message": f"{command_name} excedeu o limite de {timeout_seconds:g}s.",
            },
            None,
        )
    except OSError:
        return (
            {
                "status": "ERROR",
                "message": f"Não foi possível executar {command_name}.",
            },
            None,
        )

    if result.returncode != 0:
        return (
            {
                "status": "ERROR",
                "message": _safe_command_error(result.stderr, result.returncode),
                "exit_code": result.returncode,
            },
            None,
        )

    output = result.stdout
    encoded = output.encode("utf-8")
    if not output.strip():
        return (
            {
                "status": "ERROR",
                "message": f"{command_name} não devolveu dados.",
                "exit_code": result.returncode,
            },
            None,
        )
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        return (
            {
                "status": "ERROR",
                "message": f"A saída de {command_name} excedeu o limite de segurança.",
                "bytes": len(encoded),
            },
            None,
        )

    return (
        {
            "status": "AVAILABLE",
            "message": "Leitura concluída.",
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "exit_code": result.returncode,
        },
        output,
    )


def _nft_inventory(snapshot: dict[str, Any]) -> dict[str, int]:
    elements = snapshot["nftables"]
    tables = chains = rules = 0
    for element in elements:
        if not isinstance(element, dict):
            continue
        if "table" in element:
            tables += 1
        elif "chain" in element:
            chains += 1
        elif "rule" in element:
            rules += 1
    return {"tables": tables, "chains": chains, "rules": rules}


def _normalise_findings(findings: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        normalised.append(
            {
                "source": source,
                "category": item.get("category", source),
                "code": item.get("code", item.get("id", item.get("status", "FINDING"))),
                "status": item.get("status", "FINDING"),
                "severity": item.get("severity", "—"),
                "family": item.get("family", "—"),
                "chain": item.get("chain", "—"),
                "rule_id": item.get("rule_id", item.get("rule", "—")),
                "observed_lines": item.get("observed_lines", []),
                "description": (
                    item.get("reason")
                    or item.get("detail")
                    or item.get("message")
                    or item.get("impact")
                    or "Foi identificada uma condição que requer revisão."
                ),
            }
        )
    return normalised


def collect_live_state(
    policy: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    interval_ms: int = DEFAULT_INTERVAL_MS,
) -> dict[str, Any]:
    """Collects current firewall snapshots and returns a redacted analysis payload."""
    started = time.monotonic()
    sources: dict[str, dict[str, Any]] = {}
    snapshots: dict[str, dict[str, str]] = {}

    for family, command in (
        ("ipv4", "iptables-save"),
        ("ipv6", "ip6tables-save"),
    ):
        metadata, output = _run_read_only_command(command, (), timeout_seconds)
        sources[family] = {"label": f"{command} ({family.upper()})", **metadata}
        if output is not None:
            snapshots[family] = {
                "path": f"live:{command}",
                "sha256": metadata["sha256"],
                "text": output,
            }

    nft_metadata, nft_output = _run_read_only_command(
        "nft",
        ("-j", "list", "ruleset"),
        timeout_seconds,
    )
    sources["nftables"] = {"label": "nft -j list ruleset", **nft_metadata}

    nft_snapshot: dict[str, Any] | None = None
    nft_analysis: dict[str, Any] | None = None
    nft_inventory = {"tables": 0, "chains": 0, "rules": 0}
    if nft_output is not None:
        try:
            parsed = json.loads(nft_output)
            if not isinstance(parsed, dict) or not isinstance(parsed.get("nftables"), list):
                raise ValueError("O JSON nftables não contém uma lista nftables válida.")
            nft_snapshot = parsed
            nft_inventory = _nft_inventory(parsed)
        except (json.JSONDecodeError, ValueError):
            sources["nftables"]["status"] = "ERROR"
            sources["nftables"]["message"] = "A saída JSON de nftables é inválida."

    iptables_report: dict[str, Any] | None = None
    analysis_errors: list[str] = []
    if snapshots:
        try:
            iptables_report = analyze_firewall_snapshots(snapshots, policy=policy)
        except (ValueError, TypeError):
            analysis_errors.append("A análise dos snapshots iptables não pôde ser concluída.")

    if nft_snapshot is not None and policy is not None:
        try:
            nft_analysis = analyze_live_ruleset(policy, nft_snapshot)
        except (ValueError, TypeError):
            analysis_errors.append("A análise das base chains nftables não pôde ser concluída.")

    iptables_summary = (
        iptables_report.get("summary", {}) if iptables_report is not None else {}
    )
    families_summary: dict[str, dict[str, int]] = {}
    if iptables_report is not None:
        for family in iptables_report.get("families", []):
            structural = family.get("structural_analysis", {}).get("summary", {})
            families_summary[family.get("family", "unknown")] = {
                "chains": int(structural.get("chains_total") or 0),
                "rules": int(structural.get("rules_total") or 0),
            }

    findings: list[dict[str, Any]] = []
    if iptables_report is not None:
        findings.extend(_normalise_findings(iptables_report.get("findings", []), "iptables"))
    if nft_analysis is not None:
        findings.extend(_normalise_findings(nft_analysis.get("findings", []), "nftables"))
    findings = findings[:100]

    available_sources = sum(
        source.get("status") == "AVAILABLE" for source in sources.values()
    )
    source_errors = sum(
        source.get("status") == "ERROR" for source in sources.values()
    )

    analysis_statuses = []
    if iptables_report is not None:
        analysis_statuses.append(iptables_report.get("status", "INCONCLUSIVE"))
    if nft_analysis is not None:
        analysis_statuses.append(nft_analysis.get("status", "INCONCLUSIVE"))

    if not available_sources:
        overall_status = "ERROR"
    elif "DRIFT" in analysis_statuses:
        overall_status = "DRIFT"
    else:
        overall_status = "INCONCLUSIVE"

    summary = {
        "iptables_families": len(families_summary),
        "ipv4_chains": families_summary.get("ipv4", {}).get("chains", 0),
        "ipv4_rules": families_summary.get("ipv4", {}).get("rules", 0),
        "ipv6_chains": families_summary.get("ipv6", {}).get("chains", 0),
        "ipv6_rules": families_summary.get("ipv6", {}).get("rules", 0),
        "iptables_chains": int(iptables_summary.get("chains_total") or 0),
        "iptables_rules": int(iptables_summary.get("rules_total") or 0),
        "rule_conflicts": int(iptables_summary.get("rule_conflict_findings") or 0),
        "ssh_candidates": int(iptables_summary.get("ssh_rule_candidates") or 0),
        "chain_cycles": int(iptables_summary.get("potential_chain_cycles") or 0),
        "policy_drifts": int(iptables_summary.get("policy_drift_findings") or 0),
        "nft_tables": nft_inventory["tables"],
        "nft_chains": nft_inventory["chains"],
        "nft_rules": nft_inventory["rules"],
        "findings": len(findings),
        "sources_available": available_sources,
        "sources_with_errors": source_errors,
    }

    duration_ms = round((time.monotonic() - started) * 1000, 2)
    limitations = [
        "A recolha é feita por polling; o ciclo nominal é de 1000 ms, mas o tempo real depende da execução dos comandos e da carga do sistema.",
        "A leitura é estritamente read-only: são usados apenas iptables-save, ip6tables-save e nft -j list ruleset.",
        "A análise nftables compara atualmente políticas das base chains; não interpreta todas as expressões individuais.",
        "A análise iptables conserva as limitações documentadas do comparador e da avaliação de tráfego.",
        "INCONCLUSIVE não significa que a firewall seja segura ou insegura.",
    ]
    if policy is None:
        limitations.append("Não foi fornecida política de referência; não são calculados desvios face a uma baseline.")
    if source_errors or analysis_errors:
        limitations.append("Uma ou mais fontes não puderam ser consultadas ou analisadas nesta atualização.")

    return {
        "schema_version": "1.0",
        "generated_at_utc": _utc_now(),
        "collection_duration_ms": duration_ms,
        "refresh_interval_ms": interval_ms,
        "status": overall_status,
        "read_only": True,
        "summary": summary,
        "sources": sources,
        "iptables": {
            "status": iptables_report.get("status") if iptables_report else "UNAVAILABLE",
            "families": families_summary,
            "summary": iptables_summary,
        },
        "nftables": {
            "status": (
                nft_analysis.get("status")
                if nft_analysis
                else ("AVAILABLE" if nft_snapshot is not None else sources["nftables"]["status"])
            ),
            "inventory": nft_inventory,
            "analysis": nft_analysis,
        },
        "findings": findings,
        "limitations": limitations,
        "analysis_errors": analysis_errors,
    }


class DashboardState:
    """Thread-safe latest-state store used by the SSE endpoint."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._version = 0
        self._payload: dict[str, Any] | None = None

    def publish(self, payload: dict[str, Any]) -> int:
        with self._condition:
            self._version += 1
            self._payload = copy.deepcopy(payload)
            self._condition.notify_all()
            return self._version

    def snapshot(self) -> tuple[int, dict[str, Any] | None]:
        with self._condition:
            return self._version, copy.deepcopy(self._payload)

    def wait_for_change(
        self,
        after_version: int,
        timeout: float = 15.0,
    ) -> tuple[int, dict[str, Any] | None]:
        with self._condition:
            if self._version <= after_version:
                self._condition.wait(timeout)
            return self._version, copy.deepcopy(self._payload)


DASHBOARD_HTML = r"""<!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Estado da firewall</title>
<style>
:root { font-family: Arial, Helvetica, sans-serif; color: #202833; background: #f4f6f8; }
* { box-sizing: border-box; }
body { margin: 0; color: #202833; background: #f4f6f8; }
main { max-width: 1180px; margin: 0 auto; padding: 26px 24px 40px; }
header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; padding-bottom: 18px; border-bottom: 1px solid #d7dde4; }
h1 { margin: 0 0 6px; font-size: 24px; font-weight: 650; }
p { margin: 0; }
.subtitle { color: #5f6b78; font-size: 13px; }
.connection { text-align: right; color: #596675; font-size: 12px; }
.connection strong { display: inline-flex; align-items: center; gap: 7px; color: #475565; font-weight: 600; }
.dot { width: 8px; height: 8px; display: inline-block; border-radius: 50%; background: #9aa4af; }
.dot.online { background: #23834c; }
.dot.offline { background: #b54747; }
section { margin-top: 23px; }
h2 { margin: 0 0 11px; font-size: 15px; font-weight: 650; color: #293746; }
.metrics { display: grid; grid-template-columns: repeat(5, minmax(0,1fr)); gap: 10px; }
.metric { background: #fff; border: 1px solid #dce2e8; border-radius: 4px; padding: 13px 15px; min-height: 79px; }
.metric span { display: block; color: #687482; font-size: 11px; }
.metric strong { display: block; margin-top: 7px; color: #202b37; font-size: 22px; font-weight: 650; font-variant-numeric: tabular-nums; }
.panel { background: #fff; border: 1px solid #dce2e8; border-radius: 4px; padding: 15px 16px; }
.status { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; }
.status-PASS, .status-AVAILABLE { background: #e7f2ea; color: #216342; }
.status-DRIFT { background: #fff0d5; color: #855500; }
.status-INCONCLUSIVE { background: #f0ecf8; color: #59468a; }
.status-ERROR, .status-UNAVAILABLE { background: #fbeaec; color: #982f35; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #f7f8fa; color: #5c6876; text-align: left; font-size: 11px; font-weight: 650; }
th, td { padding: 10px 11px; vertical-align: top; border-bottom: 1px solid #e8ebef; }
tbody tr:last-child td { border-bottom: 0; }
td { color: #344150; line-height: 1.45; }
.muted { color: #6b7785; font-size: 11px; }
.small { font-size: 11px; }
.finding-description { display: block; margin-top: 4px; color: #697583; }
.empty { color: #697583; font-size: 12px; padding: 12px 0; }
.error-note { color: #923a3e; }
.meta { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 12px; color: #687482; font-size: 11px; }
.meta span { white-space: nowrap; }
footer { margin-top: 22px; padding-top: 12px; border-top: 1px solid #d7dde4; color: #77828e; font-size: 11px; line-height: 1.5; }
@media (max-width: 780px) {
  main { padding: 20px 13px 30px; }
  header { flex-direction: column; gap: 12px; }
  .connection { text-align: left; }
  .metrics { grid-template-columns: repeat(2, minmax(0,1fr)); }
  .metric:last-child { grid-column: 1 / -1; }
}
</style>
</head>
<body>
<main>
<header>
  <div><h1>Estado da firewall</h1><p class="subtitle">Análise atual das regras e políticas observadas no sistema.</p></div>
  <div class="connection"><strong><i id="connection-dot" class="dot"></i><span id="connection-text">A ligar ao serviço…</span></strong><p id="updated-at" class="muted">À espera da primeira recolha</p></div>
</header>

<section>
  <h2>Estado atual</h2>
  <div class="panel">
    <span id="overall-status" class="status status-INCONCLUSIVE">A recolher</span>
    <div class="meta"><span id="collection-time">Tempo de recolha: —</span><span id="refresh-rate">Intervalo: —</span><span id="readonly">Modo read-only</span></div>
    <p id="global-note" class="muted" style="margin-top:10px">A primeira leitura será apresentada quando terminar.</p>
  </div>
</section>

<section>
  <h2>Resumo</h2>
  <div class="metrics">
    <div class="metric"><span>Regras IPv4</span><strong id="ipv4-rules">—</strong></div>
    <div class="metric"><span>Regras IPv6</span><strong id="ipv6-rules">—</strong></div>
    <div class="metric"><span>Chains iptables</span><strong id="iptables-chains">—</strong></div>
    <div class="metric"><span>Regras nftables</span><strong id="nft-rules">—</strong></div>
    <div class="metric"><span>Descobertas atuais</span><strong id="findings-count">—</strong></div>
  </div>
</section>

<section>
  <h2>Fontes de dados</h2>
  <div class="panel table-wrap">
    <table><thead><tr><th>Fonte</th><th>Estado</th><th>Tamanho</th><th>SHA-256</th><th>Nota</th></tr></thead>
    <tbody id="sources-body"><tr><td colspan="5" class="empty">A recolher fontes…</td></tr></tbody></table>
  </div>
</section>

<section>
  <h2>Descobertas atuais</h2>
  <div class="panel table-wrap">
    <table><thead><tr><th>Origem</th><th>Estado</th><th>Regra / cadeia</th><th>Descrição</th></tr></thead>
    <tbody id="findings-body"><tr><td colspan="4" class="empty">À espera da análise…</td></tr></tbody></table>
  </div>
</section>

<section>
  <h2>Limitações da leitura</h2>
  <div class="panel"><ul id="limitations" class="muted"><li>À espera da primeira recolha.</li></ul></div>
</section>

<footer>O serviço executa apenas comandos de consulta. Não aplica, altera nem remove regras. A atualização é enviada ao browser quando cada ciclo de recolha termina; não existe garantia de latência ao nível do milissegundo.</footer>
</main>
<script>
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  let lastUpdate = 0;

  function text(id, value) {
    const node = byId(id);
    if (node) node.textContent = value == null ? "—" : String(value);
  }

  function badge(value) {
    const allowed = ["PASS", "DRIFT", "INCONCLUSIVE", "ERROR", "AVAILABLE", "UNAVAILABLE"];
    const status = String(value || "INCONCLUSIVE").toUpperCase();
    return allowed.includes(status) ? status : "INCONCLUSIVE";
  }

  function setConnection(online, message) {
    byId("connection-dot").className = online ? "dot online" : "dot offline";
    text("connection-text", message);
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value == null ? "—" : String(value);
    row.appendChild(cell);
    return cell;
  }

  function renderSources(sources) {
    const body = byId("sources-body");
    body.replaceChildren();
    for (const key of ["ipv4", "ipv6", "nftables"]) {
      const source = sources && sources[key];
      if (!source) continue;
      const row = document.createElement("tr");
      appendCell(row, source.label);
      const stateCell = document.createElement("td");
      const pill = document.createElement("span");
      const state = badge(source.status);
      pill.className = "status status-" + state;
      pill.textContent = state;
      stateCell.appendChild(pill);
      row.appendChild(stateCell);
      appendCell(row, source.bytes == null ? "—" : source.bytes + " bytes");
      appendCell(row, source.sha256 ? source.sha256.slice(0, 16) + "…" : "—", "muted");
      appendCell(row, source.message || "—");
      body.appendChild(row);
    }
    if (!body.children.length) {
      const row = document.createElement("tr");
      appendCell(row, "Sem fontes disponíveis.");
      body.appendChild(row);
    }
  }

  function renderFindings(findings) {
    const body = byId("findings-body");
    body.replaceChildren();
    for (const finding of (findings || []).slice(0, 100)) {
      const row = document.createElement("tr");
      appendCell(row, finding.source);
      const statusCell = document.createElement("td");
      const pill = document.createElement("span");
      const state = badge(finding.status);
      pill.className = "status status-" + state;
      pill.textContent = finding.status || "FINDING";
      statusCell.appendChild(pill);
      row.appendChild(statusCell);
      const rule = [finding.rule_id, finding.family, finding.chain].filter(Boolean).join(" · ");
      appendCell(row, rule || finding.code);
      const descriptionCell = appendCell(row, finding.description);
      if (Array.isArray(finding.observed_lines) && finding.observed_lines.length) {
        const evidence = document.createElement("span");
        evidence.className = "finding-description";
        evidence.textContent = "Linha(s): " + finding.observed_lines.join(", ");
        descriptionCell.appendChild(evidence);
      }
      body.appendChild(row);
    }
    if (!body.children.length) {
      const row = document.createElement("tr");
      const cell = appendCell(row, "Sem descobertas nesta recolha.");
      cell.colSpan = 4;
      body.appendChild(row);
    }
  }

  function renderLimitations(items) {
    const list = byId("limitations");
    list.replaceChildren();
    for (const item of (items || [])) {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    }
  }

  function render(data) {
    if (!data || typeof data !== "object") return;
    const status = badge(data.status);
    const overall = byId("overall-status");
    overall.className = "status status-" + status;
    overall.textContent = status;
    const summary = data.summary || {};
    text("ipv4-rules", summary.ipv4_rules);
    text("ipv6-rules", summary.ipv6_rules);
    text("iptables-chains", summary.iptables_chains);
    text("nft-rules", summary.nft_rules);
    text("findings-count", summary.findings);
    text("collection-time", "Tempo de recolha: " + (data.collection_duration_ms ?? "—") + " ms");
    text("refresh-rate", "Intervalo nominal: " + (data.refresh_interval_ms ?? "—") + " ms");
    text("global-note", status === "ERROR"
      ? "Não foi possível obter dados de nenhuma fonte."
      : status === "DRIFT"
        ? "Foram encontradas divergências na política ou na análise atual."
        : "A recolha terminou. INCONCLUSIVE não representa um resultado PASS.");
    text("updated-at", "Última atualização: " + (data.generated_at_utc || "—"));
    renderSources(data.sources);
    renderFindings(data.findings);
    renderLimitations(data.limitations);
    lastUpdate = Date.now();
  }

  const stream = new EventSource("/api/v1/events");
  stream.onopen = () => setConnection(true, "Ligação ativa");
  stream.onerror = () => setConnection(false, "A tentar restabelecer ligação");
  stream.addEventListener("snapshot", (event) => {
    try {
      render(JSON.parse(event.data));
      setConnection(true, "Ligação ativa");
    } catch (_) {
      setConnection(false, "Resposta inválida do serviço");
    }
  });
  window.setInterval(() => {
    if (!lastUpdate) return;
    const seconds = Math.max(0, Math.floor((Date.now() - lastUpdate) / 1000));
    if (seconds > 3) setConnection(false, "Dados sem atualização há " + seconds + " s");
  }, 1000);
})();
</script>
</body>
</html>
"""


class _DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(
    state: DashboardState,
    stop_event: threading.Event,
    username: str,
    password: str | None,
):
    expected_authorisation = None
    if password is not None:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        expected_authorisation = "Basic " + token

    class Handler(BaseHTTPRequestHandler):
        server_version = "CCE"
        sys_version = ""

        def _send_headers(self, status: int, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
            )

        def _authorized(self) -> bool:
            if expected_authorisation is None:
                return True
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied, expected_authorisation)

        def _unauthorized(self) -> None:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="CCE firewall dashboard", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _send_json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_headers(200, "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if not self._authorized():
                self._unauthorized()
                return

            if path == "/":
                body = DASHBOARD_HTML.encode("utf-8")
                self._send_headers(200, "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/healthz":
                self._send_json({"status": "ok", "read_only": True})
                return

            if path == "/api/v1/status":
                version, payload = state.snapshot()
                self._send_json(
                    {
                        "version": version,
                        "data": payload,
                    }
                )
                return

            if path == "/api/v1/events":
                self._send_headers(200, "text/event-stream; charset=utf-8")
                self.send_header("Connection", "keep-alive")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                cursor = -1
                try:
                    while not stop_event.is_set():
                        version, payload = state.wait_for_change(cursor, timeout=15.0)
                        if payload is None or version <= cursor:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                            continue
                        event = (
                            f"id: {version}\n"
                            "event: snapshot\n"
                            "data: "
                            + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                            + "\n\n"
                        )
                        self.wfile.write(event.encode("utf-8"))
                        self.wfile.flush()
                        cursor = version
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
                return

            body = b'{"error":"not_found"}'
            self._send_headers(404, "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format_string: str, *args: Any) -> None:
            # Do not log query strings or authentication headers.
            super().log_message(format_string, *args)

    return Handler


def _collector_loop(
    state: DashboardState,
    stop_event: threading.Event,
    policy: dict[str, Any] | None,
    interval_ms: int,
    timeout_seconds: float,
) -> None:
    interval = interval_ms / 1000
    while not stop_event.is_set():
        started = time.monotonic()
        try:
            payload = collect_live_state(
                policy=policy,
                timeout_seconds=timeout_seconds,
                interval_ms=interval_ms,
            )
        except Exception:
            payload = {
                "generated_at_utc": _utc_now(),
                "status": "ERROR",
                "read_only": True,
                "refresh_interval_ms": interval_ms,
                "summary": {},
                "sources": {},
                "findings": [],
                "limitations": ["Ocorreu um erro interno durante a recolha; consulta os logs locais do serviço."],
                "analysis_errors": ["Falha interna de recolha."],
            }
        state.publish(payload)
        elapsed = time.monotonic() - started
        stop_event.wait(max(0.0, interval - elapsed))


def serve_live_dashboard(
    host: str = "127.0.0.1",
    port: int = 8765,
    policy: dict[str, Any] | None = None,
    interval_ms: int = DEFAULT_INTERVAL_MS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    username: str = "cce",
    password_env: str = "CCE_DASHBOARD_PASSWORD",
) -> None:
    """Start the read-only live dashboard and its background firewall collector."""
    if interval_ms < 1000:
        raise ValueError("O intervalo mínimo de recolha é 1000 ms.")
    if timeout_seconds <= 0 or timeout_seconds > 30:
        raise ValueError("O timeout tem de estar entre 0 e 30 segundos.")
    if port < 1 or port > 65535:
        raise ValueError("A porta tem de estar entre 1 e 65535.")

    password = os.environ.get(password_env) if password_env else None
    validate_server_security(host, username, password)

    state = DashboardState()
    stop_event = threading.Event()
    handler = _make_handler(state, stop_event, username, password)
    server = _DashboardHTTPServer((host, port), handler)
    server.dashboard_state = state
    collector = threading.Thread(
        target=_collector_loop,
        args=(state, stop_event, policy, interval_ms, timeout_seconds),
        name="cce-firewall-collector",
        daemon=True,
    )

    scheme_url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    print(
        f"Dashboard CCE: http://{scheme_url_host}:{server.server_port}/ "
        f"(recolha nominal: {interval_ms} ms; read-only)"
    )
    if not _is_loopback_host(host):
        print(
            "AVISO: listener de rede ativo. Usa uma VPN privada ou proxy HTTPS; "
            "não exponhas HTTP diretamente à Internet."
        )
    print("Pressiona Ctrl+C para terminar.")

    collector.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        collector.join(timeout=timeout_seconds + 1)
