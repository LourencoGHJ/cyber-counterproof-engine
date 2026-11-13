"""Recolha read-only do Windows Defender Firewall via PowerShell."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import time

from datetime import datetime, timezone
from typing import Any

from cce.adapters.base import FirewallAdapter


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Import-Module NetSecurity -ErrorAction Stop

$profiles = @(
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
    ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.Name
            enabled = [string]$_.Enabled
            default_inbound_action = [string]$_.DefaultInboundAction
            default_outbound_action = [string]$_.DefaultOutboundAction
        }
    }
)

$rules = @(
    Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop |
    ForEach-Object {
        $rule = $_

        $port = Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

        $address = Get-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

        $application = Get-NetFirewallApplicationFilter `
            -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

        $service = Get-NetFirewallServiceFilter `
            -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

        $interfaces = Get-NetFirewallInterfaceFilter `
            -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

        $protocol = @()
        $localPorts = @()
        $remotePorts = @()
        $localAddresses = @()
        $remoteAddresses = @()
        $program = @()
        $serviceName = @()
        $interfaceTypes = @()
        $interfaceAliases = @()

        if ($null -ne $port) {
            $protocol = @($port.Protocol | ForEach-Object { [string]$_ })
            $localPorts = @($port.LocalPort | ForEach-Object { [string]$_ })
            $remotePorts = @($port.RemotePort | ForEach-Object { [string]$_ })
        }

        if ($null -ne $address) {
            $localAddresses = @($address.LocalAddress | ForEach-Object { [string]$_ })
            $remoteAddresses = @($address.RemoteAddress | ForEach-Object { [string]$_ })
        }

        if ($null -ne $application) {
            $program = @($application.Program | ForEach-Object { [string]$_ })
        }

        if ($null -ne $service) {
            $serviceName = @($service.Service | ForEach-Object { [string]$_ })
        }

        if ($null -ne $interfaces) {
            $interfaceTypes = @($interfaces.InterfaceType | ForEach-Object { [string]$_ })
            $interfaceAliases = @($interfaces.InterfaceAlias | ForEach-Object { [string]$_ })
        }

        [pscustomobject]@{
            id = [string]$rule.Name
            display_name = [string]$rule.DisplayName
            description = [string]$rule.Description
            enabled = [string]$rule.Enabled
            direction = [string]$rule.Direction
            action = [string]$rule.Action
            profile = [string]$rule.Profile
            group = [string]$rule.Group
            primary_status = [string]$rule.PrimaryStatus
            status = [string]$rule.Status
            policy_store_source = [string]$rule.PolicyStoreSource
            policy_store_source_type = [string]$rule.PolicyStoreSourceType
            protocol = $protocol
            local_ports = $localPorts
            remote_ports = $remotePorts
            local_addresses = $localAddresses
            remote_addresses = $remoteAddresses
            program = $program
            service = $serviceName
            interface_types = $interfaceTypes
            interface_aliases = $interfaceAliases
        }
    }
)

$result = [pscustomobject]@{
    schema_version = 1
    platform = 'windows'
    policy_store = 'ActiveStore'
    collected_at_utc = [DateTime]::UtcNow.ToString('o')
    profiles = $profiles
    rules = $rules
}

ConvertTo-Json -InputObject $result -Depth 10 -Compress
"""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None



def _normalized_text(value: Any) -> str:
    """Normaliza texto recebido da recolha PowerShell."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


class WindowsDefenderFirewallAdapter(FirewallAdapter):
    adapter_id = "windows.defender-firewall"
    platform = "windows"

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds tem de ser superior a zero.")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _powershell() -> str | None:
        for name in (
            "powershell.exe",
            "powershell",
            "pwsh.exe",
            "pwsh",
        ):
            executable = shutil.which(name)
            if executable:
                return executable
        return None

    def probe(self) -> dict[str, Any]:
        executable = self._powershell()
        correct_platform = platform.system() == "Windows"

        return {
            "adapter_id": self.adapter_id,
            "platform": self.platform,
            "available": bool(executable and correct_platform),
            "status": (
                "available"
                if executable and correct_platform
                else "platform_mismatch"
                if not correct_platform
                else "tool_not_found"
            ),
            "executables": {"powershell": executable},
            "permission_probe": "not_performed",
            "read_only": True,
            "note": (
                "A presença de PowerShell não comprova a disponibilidade "
                "do módulo NetSecurity. Essa verificação ocorre na recolha."
            ),
        }

    def collect(self) -> dict[str, Any]:
        if platform.system() != "Windows":
            raise RuntimeError(
                "Windows Defender Firewall só pode ser consultado no Windows."
            )

        executable = self._powershell()
        if not executable:
            raise RuntimeError(
                "PowerShell não encontrado. Instala ou disponibiliza "
                "Windows PowerShell."
            )

        command = [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_SCRIPT,
        ]

        started = time.monotonic()

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
                f"Consulta Windows excedeu {self.timeout_seconds:g} segundos."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Não foi possível iniciar PowerShell: {exc}"
            ) from exc

        if result.returncode != 0:
            error = result.stderr.strip() or "erro PowerShell desconhecido"
            raise RuntimeError(
                "Falha na recolha Windows Defender Firewall: " + error
            )

        raw = result.stdout.strip()

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "PowerShell não devolveu JSON válido."
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError("Snapshot Windows inválido.")

        profiles = _as_list(payload.get("profiles"))
        rules = _as_list(payload.get("rules"))

        if not isinstance(profiles, list) or not isinstance(rules, list):
            raise RuntimeError("Estrutura de regras Windows inválida.")

        enabled_rules = [
            rule for rule in rules
            if isinstance(rule, dict) and _as_bool(rule.get("enabled")) is True
        ]

        summary = {
            "profiles_total": len(profiles),
            "profiles_enabled": sum(
                1 for item in profiles
                if isinstance(item, dict)
                and _as_bool(item.get("enabled")) is True
            ),
            "rules_total": len(rules),
            "rules_enabled": len(enabled_rules),
            "rules_disabled": len(rules) - len(enabled_rules),
            "inbound_rules": sum(
                1 for rule in rules
                if isinstance(rule, dict)
                and _normalized_text(rule.get("direction")) == "inbound"
            ),
            "outbound_rules": sum(
                1 for rule in rules
                if isinstance(rule, dict)
                and _normalized_text(rule.get("direction")) == "outbound"
            ),
            "allow_rules": sum(
                1 for rule in rules
                if isinstance(rule, dict)
                and _normalized_text(rule.get("action")) == "allow"
            ),
            "block_rules": sum(
                1 for rule in rules
                if isinstance(rule, dict)
                and _normalized_text(rule.get("action")) == "block"
            ),
        }

        return {
            "schema_version": 1,
            "adapter_id": self.adapter_id,
            "platform": "windows",
            "source": "Windows Defender Firewall ActiveStore",
            "policy_store": "ActiveStore",
            "status": "INCONCLUSIVE",
            "partial": True,
            "collected_at_utc": (
                payload.get("collected_at_utc")
                or datetime.now(timezone.utc).isoformat()
            ),
            "summary": summary,
            "profiles": profiles,
            "rules": rules,
            "evidence": {
                "windows_active_store": {
                    "sha256": hashlib.sha256(
                        raw.encode("utf-8")
                    ).hexdigest()
                }
            },
            "warnings": [],
            "limitations": [
                "A recolha não representa uma avaliação de conformidade.",
                "Não existe ainda comparação semântica Windows com a policy CCE.",
                "Não são avaliadas regras dinâmicas de aplicações fora do ActiveStore.",
                "A interpretação da precedência de regras não está implementada.",
                "O resultado mantém-se INCONCLUSIVE até existir um analisador Windows.",
            ],
            "collection_duration_ms": round(
                (time.monotonic() - started) * 1000, 2
            ),
        }
