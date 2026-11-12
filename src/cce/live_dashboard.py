"""Dashboard de firewall com atualização contínua e recolha read-only."""

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
from cce.models import load_json, validate_policy
from cce.snapshot_analysis import analyze_firewall_snapshots


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_findings(values: Any) -> list[dict[str, Any]]:
    """Constrói uma lista limitada de findings sem divulgar regras ou seletores."""
    if not isinstance(values, list):
        return []

    allowed = (
        "code",
        "category",
        "policy_category",
        "status",
        "severity",
        "family",
        "table",
        "chain",
        "hook",
        "rule_id",
        "observed_lines",
        "impact",
        "reason",
        "detail",
        "expected",
        "observed",
    )
    result: list[dict[str, Any]] = []
    for item in values[:200]:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                key: item[key]
                for key in allowed
                if key in item
                and isinstance(item[key], (str, int, float, bool, list, type(None)))
            }
        )
    return result


class LiveSnapshotCollector:
    """Recolhe snapshots de firewall através de comandos fixos e read-only."""

    def __init__(
        self,
        policy_path: str,
        source: str = "auto",
        timeout_seconds: float = 8.0,
    ) -> None:
        if source not in {"auto", "iptables", "nftables"}:
            raise ValueError("source tem de ser auto, iptables ou nftables.")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds tem de ser superior a zero.")

        self.policy_path = policy_path
        self.policy = load_json(policy_path)
        errors = validate_policy(self.policy)
        if errors:
            raise ValueError("Política inválida: " + "; ".join(errors))

        self.requested_source = source
        self.timeout_seconds = timeout_seconds

    def _resolve_source(self) -> str:
        if self.requested_source != "auto":
            return self.requested_source
        # Preferimos iptables-save quando está instalado porque a análise
        # semântica do CCE para esta fonte é mais profunda. Caso contrário,
        # usamos nftables com o âmbito atualmente suportado pelo adaptador live.
        if shutil.which("iptables-save"):
            return "iptables"
        if shutil.which("nft"):
            return "nftables"
        raise RuntimeError(
            "Não foi encontrado iptables-save nem nft. "
            "Executa o serviço no host Linux que gere a firewall."
        )

    def _run_read_only(self, executable: str, args: list[str]) -> subprocess.CompletedProcess[str]:
        command = [executable, *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"A consulta {executable} excedeu {self.timeout_seconds:g} segundos."
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Não foi possível executar {executable}: {exc}") from exc

        if result.returncode != 0:
            message = result.stderr.strip() or f"código de saída {result.returncode}"
            if "operation not permitted" in message.lower() or "permission denied" in message.lower():
                message += ". Verifica as permissões read-only necessárias no host Linux."
            raise RuntimeError(f"{executable} falhou: {message}")
        return result

    def _collect_iptables(self) -> dict[str, Any]:
        snapshots: dict[str, dict[str, str]] = {}
        warnings: list[str] = []
        commands = (
            ("ipv4", "iptables-save"),
            ("ipv6", "ip6tables-save"),
        )

        for family, binary in commands:
            executable = shutil.which(binary)
            if not executable:
                warnings.append(f"{binary} não está instalado; {family} não foi recolhido.")
                continue
            try:
                result = self._run_read_only(executable, [])
            except RuntimeError as exc:
                warnings.append(f"{family}: {exc}")
                continue

            raw = result.stdout
            if not raw.strip():
                warnings.append(f"{binary} devolveu um snapshot vazio.")
                continue
            snapshots[family] = {
                "path": f"live://{binary}",
                "sha256": _sha256(raw),
                "text": raw,
            }

        if not snapshots:
            raise RuntimeError(
                "Não foi possível recolher snapshots iptables. "
                + " ".join(warnings)
            )

        report = analyze_firewall_snapshots(snapshots, policy=self.policy)
        status = report.get("status", "INCONCLUSIVE")
        summary = report.get("summary", {})
        if warnings and status != "DRIFT":
            status = "INCONCLUSIVE"

        limitations = list(report.get("limitations", []))
        limitations.append(
            "A fonte iptables-save pode não incluir regras nftables nativas "
            "que não sejam expostas pela camada de compatibilidade iptables."
        )
        if warnings:
            limitations.extend(warnings)

        return {
            "updated_at_utc": _utc_now(),
            "status": status,
            "source": "iptables-save",
            "scope": "semantic_iptables_snapshot_analysis",
            "partial": bool(warnings),
            "warnings": warnings,
            "summary": summary,
            "findings": _public_findings(report.get("findings", [])),
            "limitations": limitations,
            "evidence": {
                family: {
                    "source": snapshots[family]["path"],
                    "sha256": snapshots[family]["sha256"],
                }
                for family in snapshots
            },
        }

    def _collect_nftables(self) -> dict[str, Any]:
        executable = shutil.which("nft")
        if not executable:
            raise RuntimeError("Comando nft não encontrado no host Linux.")

        result = self._run_read_only(executable, ["-j", "list", "ruleset"])
        raw = result.stdout
        try:
            snapshot = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("nft devolveu JSON inválido.") from exc

        analysis = analyze_live_ruleset(self.policy, snapshot)
        return {
            "updated_at_utc": _utc_now(),
            "status": analysis.get("status", "INCONCLUSIVE"),
            "source": "nftables",
            "scope": analysis.get("scope", "base_chain_policies_only"),
            "partial": True,
            "warnings": [],
            "summary": analysis.get("summary", {}),
            "findings": _public_findings(analysis.get("findings", [])),
            "limitations": list(analysis.get("limitations", [])),
            "evidence": {"nftables": {"sha256": _sha256(raw)}},
        }

    def collect(self) -> dict[str, Any]:
        """Executa uma recolha e devolve sempre um estado apresentável pelo UI."""
        started = time.monotonic()
        try:
            source = self._resolve_source()
            result = (
                self._collect_iptables()
                if source == "iptables"
                else self._collect_nftables()
            )
        except Exception as exc:  # O serviço deve continuar a atualizar o estado de erro.
            result = {
                "updated_at_utc": _utc_now(),
                "status": "ERROR",
                "source": self.requested_source,
                "scope": "collection_failed",
                "partial": True,
                "warnings": [],
                "summary": {},
                "findings": [],
                "limitations": [
                    "A recolha falhou; não é possível inferir o estado atual da firewall."
                ],
                "error": f"{type(exc).__name__}: {exc}",
                "evidence": {},
            }

        result["collection_duration_ms"] = round(
            (time.monotonic() - started) * 1000,
            2,
        )
        return result


class LiveState:
    """Partilha snapshots entre o recolhedor e clientes HTTP/SSE."""

    def __init__(
        self,
        collector: LiveSnapshotCollector,
        interval_seconds: float,
    ) -> None:
        if interval_seconds < 1.0:
            raise ValueError(
                "O intervalo mínimo é 1 segundo para limitar a carga de recolha."
            )
        self.collector = collector
        self.interval_seconds = interval_seconds
        self.condition = threading.Condition()
        self.stop_event = threading.Event()
        self.sequence = 0
        self.current: dict[str, Any] = {
            "updated_at_utc": None,
            "status": "STARTING",
            "source": collector.requested_source,
            "scope": "not_collected",
            "partial": True,
            "warnings": [],
            "summary": {},
            "findings": [],
            "limitations": [],
            "evidence": {},
            "interval_seconds": interval_seconds,
            "sequence": 0,
        }
        self.thread = threading.Thread(
            target=self._run,
            name="cce-firewall-collector",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        with self.condition:
            self.condition.notify_all()
        if self.thread.is_alive():
            self.thread.join(timeout=5)

    def snapshot(self) -> dict[str, Any]:
        with self.condition:
            value = copy.deepcopy(self.current)
            value["sequence"] = self.sequence
            value["interval_seconds"] = self.interval_seconds
            return value

    def wait_for_update(
        self,
        previous_sequence: int,
        timeout: float = 15.0,
    ) -> tuple[int, dict[str, Any] | None]:
        with self.condition:
            self.condition.wait_for(
                lambda: self.sequence > previous_sequence or self.stop_event.is_set(),
                timeout=timeout,
            )
            if self.sequence <= previous_sequence:
                return self.sequence, None
            return self.sequence, copy.deepcopy(self.current)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            result = self.collector.collect()
            with self.condition:
                self.sequence += 1
                result["sequence"] = self.sequence
                result["interval_seconds"] = self.interval_seconds
                self.current = result
                self.condition.notify_all()
            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.0, self.interval_seconds - elapsed))


LIVE_HTML = r"""<!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Firewall — Estado em tempo real</title>
<style>
:root{font-family:Arial,Helvetica,sans-serif;color:#202833;background:#f3f5f7}
*{box-sizing:border-box}
body{margin:0;background:#f3f5f7;color:#202833}
main{max-width:1120px;margin:0 auto;padding:28px 24px 42px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding-bottom:18px;border-bottom:1px solid #d9dee5}
h1{font-size:25px;font-weight:650;margin:0 0 6px}
p{line-height:1.5}
.subtitle{margin:0;color:#637080;font-size:13px}
.connection{font-size:12px;color:#566473;white-space:nowrap;padding-top:5px}
.connection::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;background:#c48b2d;margin-right:7px}
.connection.connected::before{background:#2d8a58}
.connection.disconnected::before{background:#c13c48}
section{margin-top:24px}
h2{font-size:16px;font-weight:650;margin:0 0 12px}
.summary{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:#fff;border:1px solid #dce2e8;border-radius:4px;padding:15px 17px}
.badge{display:inline-block;border-radius:3px;padding:5px 8px;font-size:11px;font-weight:700;background:#edf0f2;color:#4c5968}
.badge-PASS{background:#e8f3ec;color:#216342}.badge-DRIFT{background:#fff2d8;color:#855500}
.badge-ERROR{background:#fbeaec;color:#982f35}.badge-INCONCLUSIVE{background:#f0ecf8;color:#59468a}
.description{font-size:13px;color:#4f5c69}
.meta{margin-left:auto;font-size:11px;color:#697583}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid #dce2e8;background:#fff;border-radius:4px}
.metric{padding:14px 15px;border-right:1px solid #e5e9ed}.metric:last-child{border:0}
.label{display:block;font-size:11px;color:#657180}.value{display:block;font-size:22px;font-weight:650;margin-top:7px;font-variant-numeric:tabular-nums}
.panel{border:1px solid #dce2e8;background:#fff;border-radius:4px;padding:15px 16px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:10px;color:#586675;background:#f7f8fa;border-bottom:1px solid #dce2e8;font-size:11px}
td{padding:10px;vertical-align:top;border-bottom:1px solid #e8ebef;line-height:1.45;color:#354150}
tbody tr:last-child td{border-bottom:0}
code{font-family:Consolas,'Courier New',monospace;font-size:11px;color:#315474}
.muted{color:#697583;font-size:12px}
.warning{margin-top:10px;padding:10px 12px;border:1px solid #ecd7a9;background:#fff9eb;color:#77571e;font-size:12px;border-radius:3px}
.empty{padding:15px 0;color:#697583;font-size:13px}
footer{margin-top:24px;padding-top:12px;border-top:1px solid #d9dee5;color:#75808c;font-size:11px;line-height:1.5}
@media(max-width:700px){main{padding:20px 13px 30px}header{flex-direction:column;gap:7px}h1{font-size:22px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{border-bottom:1px solid #e5e9ed}.metric:nth-child(2n){border-right:0}.metric:last-child{grid-column:1/-1;border:0}.meta{margin-left:0;width:100%}table{min-width:650px}}
@media print{body{background:#fff}main{max-width:none;padding:0}.connection{display:none}.panel,.summary,.metrics{break-inside:avoid}}
</style>
</head>
<body>
<main>
<header>
  <div><h1>Estado da firewall</h1><p class="subtitle">Auditoria read-only · atualizações automáticas</p></div>
  <div id="connection" class="connection">A ligar ao serviço…</div>
</header>
<section>
  <h2>Estado atual</h2>
  <div class="summary">
    <span id="status" class="badge">STARTING</span>
    <span id="description" class="description">A aguardar a primeira recolha.</span>
    <span id="updated" class="meta">Ainda sem atualização</span>
  </div>
  <div id="warnings"></div>
</section>
<section>
  <h2>Resumo da recolha</h2>
  <div class="metrics">
    <div class="metric"><span class="label">Fonte</span><strong id="source" class="value">—</strong></div>
    <div class="metric"><span class="label">Regras</span><strong id="rules" class="value">—</strong></div>
    <div class="metric"><span class="label">Chains</span><strong id="chains" class="value">—</strong></div>
    <div class="metric"><span class="label">Descobertas</span><strong id="findings-count" class="value">—</strong></div>
    <div class="metric"><span class="label">Recolha (ms)</span><strong id="duration" class="value">—</strong></div>
  </div>
  <p id="coverage" class="muted"></p>
</section>
<section>
  <h2>Descobertas atuais</h2>
  <div class="panel table-wrap">
    <table><thead><tr><th>Estado</th><th>Família</th><th>Chain</th><th>Regra</th><th>Descrição</th><th>Linhas</th></tr></thead>
    <tbody id="findings"><tr><td colspan="6" class="muted">A aguardar dados.</td></tr></tbody></table>
  </div>
</section>
<section>
  <h2>Atualizações recentes</h2>
  <div class="panel table-wrap">
    <table><thead><tr><th>Hora UTC</th><th>Estado</th><th>Descobertas</th><th>Fonte</th></tr></thead>
    <tbody id="history"><tr><td colspan="4" class="muted">A aguardar dados.</td></tr></tbody></table>
  </div>
</section>
<section>
  <h2>Limitações da fonte</h2>
  <div id="limitations" class="panel"><p class="empty">A aguardar dados.</p></div>
</section>
<footer>Os dados são recolhidos pelo serviço CCE no host Linux. A recolha é apenas de leitura; nenhuma regra é aplicada ou alterada. O intervalo representa a frequência de consulta, não uma garantia de latência de milissegundos.</footer>
</main>
<script>
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const connection = byId("connection");
  const history = [];
  const descriptions = {
    PASS: "Sem divergências reportadas nos campos analisados.",
    DRIFT: "Foram encontradas divergências face à política.",
    ERROR: "A recolha falhou; o estado da firewall não está confirmado.",
    INCONCLUSIVE: "A evidência disponível não permite uma conclusão definitiva.",
    STARTING: "A aguardar a primeira recolha."
  };

  function setText(id, value) {
    byId(id).textContent = value === undefined || value === null || value === "" ? "—" : String(value);
  }

  function cell(row, value, useCode = false) {
    const td = document.createElement("td");
    if (useCode) {
      const code = document.createElement("code");
      code.textContent = value === undefined || value === null ? "—" : String(value);
      td.appendChild(code);
    } else {
      td.textContent = value === undefined || value === null ? "—" : String(value);
    }
    row.appendChild(td);
  }

  function updateFindings(items) {
    const body = byId("findings");
    body.replaceChildren();
    if (!Array.isArray(items) || items.length === 0) {
      const row = document.createElement("tr");
      cell(row, "Não foram registadas descobertas nesta recolha.");
      const td = row.firstElementChild;
      td.colSpan = 6;
      td.className = "muted";
      body.appendChild(row);
      return;
    }
    for (const item of items.slice(0, 100)) {
      const row = document.createElement("tr");
      cell(row, item.status || item.severity || item.code);
      cell(row, item.family);
      cell(row, item.chain);
      cell(row, item.rule_id, true);
      cell(row, item.reason || item.detail || item.code || item.category);
      cell(row, Array.isArray(item.observed_lines) ? item.observed_lines.join(", ") : "—");
      body.appendChild(row);
    }
  }

  function updateHistory(snapshot) {
    history.unshift({
      time: snapshot.updated_at_utc,
      status: snapshot.status,
      findings: Array.isArray(snapshot.findings) ? snapshot.findings.length : 0,
      source: snapshot.source
    });
    if (history.length > 25) history.length = 25;
    const body = byId("history");
    body.replaceChildren();
    for (const item of history) {
      const row = document.createElement("tr");
      cell(row, item.time);
      cell(row, item.status);
      cell(row, item.findings);
      cell(row, item.source);
      body.appendChild(row);
    }
  }

  function render(snapshot) {
    const status = String(snapshot.status || "INCONCLUSIVE").toUpperCase();
    const badge = byId("status");
    badge.textContent = status;
    badge.className = "badge badge-" + (["PASS","DRIFT","ERROR","INCONCLUSIVE"].includes(status) ? status : "UNKNOWN");
    setText("description", snapshot.error || descriptions[status] || "Resultado recebido do CCE.");
    setText("updated", snapshot.updated_at_utc ? "Atualizado " + snapshot.updated_at_utc : "Ainda sem atualização");
    setText("source", snapshot.source);
    const summary = snapshot.summary || {};
    setText("rules", summary.rules_total ?? summary.rules_semantically_compared);
    setText("chains", summary.chains_total ?? summary.base_chains);
    setText("findings-count", Array.isArray(snapshot.findings) ? snapshot.findings.length : 0);
    setText("duration", snapshot.collection_duration_ms);
    setText("coverage", snapshot.scope ? "Âmbito: " + snapshot.scope + " · Intervalo configurado: " + snapshot.interval_seconds + " s" : "");
    updateFindings(snapshot.findings || []);
    updateHistory(snapshot);
    const warnings = [...(snapshot.warnings || []), ...(snapshot.partial ? ["Recolha parcial; consulta as limitações antes de interpretar o resultado."] : [])];
    const warningBox = byId("warnings");
    warningBox.replaceChildren();
    for (const warning of warnings) {
      const p = document.createElement("p");
      p.className = "warning";
      p.textContent = warning;
      warningBox.appendChild(p);
    }
    const limits = byId("limitations");
    limits.replaceChildren();
    const items = snapshot.limitations || [];
    if (!items.length) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "Sem limitações adicionais reportadas.";
      limits.appendChild(p);
    } else {
      const ul = document.createElement("ul");
      for (const item of items) {
        const li = document.createElement("li");
        li.textContent = item;
        ul.appendChild(li);
      }
      limits.appendChild(ul);
    }
  }

  fetch("/api/v1/status", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.json();
    })
    .then(render)
    .catch(() => { connection.textContent = "Serviço indisponível"; connection.className = "connection disconnected"; });

  const events = new EventSource("/events");
  events.onopen = () => {
    connection.textContent = "Ligação ativa · fluxo SSE";
    connection.className = "connection connected";
  };
  events.onmessage = (event) => {
    try { render(JSON.parse(event.data)); }
    catch (_) { connection.textContent = "Evento inválido"; connection.className = "connection disconnected"; }
  };
  events.onerror = () => {
    connection.textContent = "A reconectar…";
    connection.className = "connection disconnected";
  };
})();
</script>
</body>
</html>
"""


def validate_remote_access(
    host: str,
    allow_remote: bool,
    token: str | None,
    trusted_transport: bool,
) -> bool:
    """Valida a configuração de acesso remoto; devolve se exige autenticação."""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"

    if is_loopback:
        return False
    if not allow_remote:
        raise ValueError(
            "O serviço está limitado a localhost. Usa --allow-remote "
            "apenas numa rede privada protegida."
        )
    if not token or len(token) < 32:
        raise ValueError(
            "Acesso remoto exige um token com pelo menos 32 caracteres "
            "na variável de ambiente configurada."
        )
    if not trusted_transport:
        raise ValueError(
            "Acesso remoto exige --trusted-transport e uma VPN ou proxy HTTPS "
            "com controlo de acesso."
        )
    return True


def create_dashboard_server(
    host: str,
    port: int,
    state: LiveState,
    token: str | None = None,
    allow_remote: bool = False,
    trusted_transport: bool = False,
) -> ThreadingHTTPServer:
    require_auth = validate_remote_access(
        host,
        allow_remote,
        token,
        trusted_transport,
    )

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "CCE-Dashboard"
        sys_version = ""

        def _authorised(self) -> bool:
            if not require_auth:
                return True
            expected = "Basic " + base64.b64encode(
                ("cce:" + str(token)).encode("utf-8")
            ).decode("ascii")
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied, expected)

        def _headers(self, content_type: str) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; connect-src 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )

        def _send_json(self, value: dict[str, Any], code: int = 200) -> None:
            payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self._headers("application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _check_auth(self) -> bool:
            if self._authorised():
                return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="CCE firewall dashboard"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/healthz":
                self._send_json({"ok": True})
                return
            if not self._check_auth():
                return

            if path == "/":
                payload = LIVE_HTML.encode("utf-8")
                self.send_response(200)
                self._headers("text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if path == "/api/v1/status":
                self._send_json(state.snapshot())
                return

            if path == "/events":
                self.send_response(200)
                self._headers("text/event-stream; charset=utf-8")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                sequence = -1
                try:
                    while not state.stop_event.is_set():
                        current_sequence, current = state.wait_for_update(
                            sequence,
                            timeout=15,
                        )
                        if current is None:
                            self.wfile.write(b": keep-alive\n\n")
                            self.wfile.flush()
                            continue
                        sequence = current_sequence
                        payload = json.dumps(
                            current,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        self.wfile.write(
                            ("id: " + str(sequence) + "\n").encode("ascii")
                        )
                        self.wfile.write(
                            ("data: " + payload + "\n\n").encode("utf-8")
                        )
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
                return

            self._send_json({"error": "not_found"}, code=404)

        def log_message(self, format: str, *args: Any) -> None:
            # Não regista headers de autenticação nem dados dos snapshots.
            return

    class CCEThreadingHTTPServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = CCEThreadingHTTPServer((host, port), DashboardHandler)
    return server


def serve_live_dashboard(
    policy_path: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    source: str = "auto",
    interval_seconds: float = 1.0,
    allow_remote: bool = False,
    token_env: str = "CCE_DASHBOARD_TOKEN",
    trusted_transport: bool = False,
) -> None:
    """Inicia o recolhedor read-only e o servidor HTTP/SSE."""
    collector = LiveSnapshotCollector(policy_path, source=source)
    token = os.environ.get(token_env)
    state = LiveState(collector, interval_seconds)
    server = create_dashboard_server(
        host,
        port,
        state,
        token=token,
        allow_remote=allow_remote,
        trusted_transport=trusted_transport,
    )

    state.start()
    actual_host, actual_port = server.server_address[:2]
    print(
        f"Dashboard CCE: http://{actual_host}:{actual_port} "
        f"| fonte={source} | intervalo={interval_seconds:g}s"
    )
    if actual_host in {"0.0.0.0", "::"}:
        print(
            "Acesso remoto ativo: protege o serviço com o transporte privado/"
            "HTTPS configurado e mantém o token fora do histórico do terminal."
        )
    print("Recolha read-only. Ctrl+C para terminar.")

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nA terminar o dashboard CCE.")
    finally:
        state.stop()
        server.server_close()
