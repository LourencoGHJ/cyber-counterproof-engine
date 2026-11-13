"""Seleção do adaptador adequado à plataforma detetada."""

from __future__ import annotations

from cce.adapters.base import FirewallAdapter
from cce.platform.detection import detect_platform


def create_firewall_adapter(
    policy_path: str,
    source: str = "auto",
    timeout_seconds: float = 8.0,
    sudo_readonly: bool = False,
    system: str | None = None,
) -> FirewallAdapter:
    detected_system = system or detect_platform()["host"]["system"]

    if detected_system == "linux":
        from cce.adapters.linux.netfilter import LinuxNetfilterAdapter

        return LinuxNetfilterAdapter(
            policy_path=policy_path,
            source=source,
            timeout_seconds=timeout_seconds,
            sudo_readonly=sudo_readonly,
        )

    if detected_system == "windows":
        if sudo_readonly:
            raise ValueError(
                "--sudo-readonly é exclusivo do adaptador Linux."
            )
        if source != "auto":
            raise ValueError(
                "As opções iptables/nftables não se aplicam ao Windows."
            )

        from cce.adapters.windows.defender import (
            WindowsDefenderFirewallAdapter,
        )

        return WindowsDefenderFirewallAdapter(
            timeout_seconds=timeout_seconds,
        )

    raise ValueError(
        f"Sistema operativo não suportado pelo CCE: {detected_system}."
    )
