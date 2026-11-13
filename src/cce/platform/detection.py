"""Deteção read-only do sistema operativo e ferramentas de firewall."""

from __future__ import annotations

import os
import platform
import shutil
from typing import Any


def _which(name: str) -> str | None:
    return shutil.which(name)


def _is_admin(system: str) -> bool:
    if system == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False

    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    return False


def _adapter(
    adapter_id: str,
    name: str,
    implementation: str,
    executables: dict[str, str | None],
    privilege_required: bool = True,
    note: str = "",
) -> dict[str, Any]:
    available = any(executables.values())

    if implementation == "implemented":
        status = "available" if available else "tool_not_found"
    else:
        status = "planned_with_tool" if available else "planned"

    return {
        "id": adapter_id,
        "name": name,
        "implementation": implementation,
        "status": status,
        "available": available,
        "executables": executables,
        "privilege_required": privilege_required,
        "permission_probe": "not_performed",
        "note": note,
    }


def detect_platform() -> dict[str, Any]:
    """Deteta o host sem executar comandos de firewall."""

    raw_system = platform.system()

    systems = {
        "Linux": "linux",
        "Windows": "windows",
    }

    system = systems.get(raw_system, "unknown")
    distribution = None

    if system == "linux":
        try:
            distribution = platform.freedesktop_os_release().get(
                "PRETTY_NAME"
            )
        except (AttributeError, OSError):
            distribution = None

    host = {
        "system": system,
        "system_name": raw_system,
        "distribution": distribution,
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }

    admin = _is_admin(system)

    privileges = {
        "is_admin": admin,
        "context": "administrator" if admin else "standard_user",
        "sudo_available": bool(_which("sudo")) if system != "windows" else False,
    }

    adapters: list[dict[str, Any]] = []

    if system == "linux":
        adapters.append(
            _adapter(
                "linux.iptables",
                "iptables / ip6tables",
                "implemented",
                {
                    "iptables-save": _which("iptables-save"),
                    "ip6tables-save": _which("ip6tables-save"),
                },
                note="Recolha através de snapshots iptables-save.",
            )
        )

        adapters.append(
            _adapter(
                "linux.nftables",
                "nftables",
                "implemented",
                {"nft": _which("nft")},
                note=(
                    "Análise atual limitada às políticas das base chains "
                    "e à estrutura suportada."
                ),
            )
        )

    elif system == "windows":
        powershell = (
            _which("powershell.exe")
            or _which("powershell")
            or _which("pwsh.exe")
            or _which("pwsh")
        )

        adapters.append(
            _adapter(
                "windows.defender-firewall",
                "Windows Defender Firewall",
                "implemented",
                {"powershell": powershell},
                note=(
                    "Adaptador Windows Defender implementado. "
                    "A disponibilidade do módulo NetSecurity "
                    "é confirmada durante a recolha."
                ),
            )
        )

    return {
        "schema_version": 1,
        "host": host,
        "privileges": privileges,
        "security": {
            "default_mode": "read-only",
            "remote_access_default": False,
            "firewall_commands_executed": False,
        },
        "dashboard": {
            "http_server_available": True,
            "server_sent_events_available": True,
            "default_bind": "127.0.0.1",
        },
        "adapters": adapters,
        "limitations": [
            "A deteção de executáveis não comprova permissões de acesso.",
            "Não foi executada qualquer consulta às regras da firewall.",
            "A disponibilidade de um adaptador não significa cobertura semântica total.",
            "Adaptador Windows implementado; validação numa máquina Windows real ainda pendente.",
            "A deteção do PowerShell não confirma a disponibilidade do módulo NetSecurity.",
        ],
    }


def format_platform_info(info: dict[str, Any]) -> str:
    host = info["host"]
    privileges = info["privileges"]

    lines = [
        "CCE PLATFORM INFORMATION",
        "=" * 48,
        f"Sistema:       {host['system_name']}",
        f"Distribuição:  {host['distribution'] or 'N/D'}",
        f"Release:       {host['release']}",
        f"Arquitetura:   {host['architecture']}",
        f"Python:        {host['python_version']}",
        f"Privilégios:   {privileges['context']}",
        f"Sudo:          {'Available' if privileges['sudo_available'] else 'N/A'}",
        "",
        "FIREWALL ADAPTERS",
        "-" * 48,
    ]

    if not info["adapters"]:
        lines.append("Nenhum adaptador conhecido.")
    else:
        for adapter in info["adapters"]:
            lines.append(
                f"{adapter['name']}: {adapter['status']} "
                f"| implementação={adapter['implementation']}"
            )
            for name, path in adapter["executables"].items():
                lines.append(f"  {name}: {path or 'não encontrado'}")

    lines.extend([
        "",
        "SECURITY",
        "-" * 48,
        "Modo: Read-only",
        "Consultas reais à firewall: não executadas",
        "Acesso remoto por defeito: desativado",
        "",
        "LIMITAÇÕES",
    ])

    lines.extend(f"- {item}" for item in info["limitations"])

    return "\n".join(lines)


def format_doctor(info: dict[str, Any]) -> str:
    host = info["host"]
    lines = [
        "CCE DOCTOR",
        "=" * 48,
        f"[OK] Sistema identificado: {host['system_name']}",
        f"[OK] Python: {host['python_version']}",
        f"[OK] Arquitetura: {host['architecture']}",
        "[OK] Dashboard HTTP/SSE disponível na implementação",
        "",
        "DIAGNÓSTICO DE ADAPTADORES",
        "-" * 48,
    ]

    for adapter in info["adapters"]:
        if adapter["status"] == "available":
            marker = "AVAILABLE"
        elif adapter["status"] == "tool_not_found":
            marker = "MISSING TOOL"
        elif adapter["status"] == "planned_with_tool":
            marker = "PLANNED / TOOL FOUND"
        else:
            marker = "PLANNED"

        lines.append(f"[{marker}] {adapter['name']}")

    lines.extend([
        "",
        "SEGURANÇA",
        "-" * 48,
        "[OK] Diagnóstico sem alterar a firewall",
        "[OK] Sem execução de comandos administrativos",
        "[OK] Acesso remoto desativado por defeito",
        "",
        "Nota: disponibilidade de ferramentas não comprova permissões.",
    ])

    return "\n".join(lines)
