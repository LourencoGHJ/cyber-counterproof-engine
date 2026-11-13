"""Adaptador Linux que reutiliza o motor de recolha Netfilter existente."""

from __future__ import annotations

import shutil
from typing import Any

from cce.adapters.base import FirewallAdapter
from cce.live_dashboard import LiveSnapshotCollector


class LinuxNetfilterAdapter(FirewallAdapter):
    adapter_id = "linux.netfilter"
    platform = "linux"

    def __init__(
        self,
        policy_path: str,
        source: str = "auto",
        timeout_seconds: float = 8.0,
        sudo_readonly: bool = False,
    ) -> None:
        if source not in {"auto", "iptables", "nftables"}:
            raise ValueError("Fonte Linux inválida.")

        self.source = source
        self.collector = LiveSnapshotCollector(
            policy_path,
            source=source,
            timeout_seconds=timeout_seconds,
            sudo_readonly=sudo_readonly,
        )

    def probe(self) -> dict[str, Any]:
        executables = {
            "iptables-save": shutil.which("iptables-save"),
            "ip6tables-save": shutil.which("ip6tables-save"),
            "nft": shutil.which("nft"),
        }

        if self.source == "iptables":
            relevant = {
                key: executables[key]
                for key in ("iptables-save", "ip6tables-save")
            }
        elif self.source == "nftables":
            relevant = {"nft": executables["nft"]}
        else:
            relevant = executables

        available = any(relevant.values())

        return {
            "adapter_id": self.adapter_id,
            "platform": self.platform,
            "available": available,
            "requested_source": self.source,
            "executables": executables,
            "permission_probe": "not_performed",
            "read_only": True,
            "limitations": [
                "A disponibilidade do executável não comprova permissões.",
                "A análise nftables tem cobertura semântica limitada.",
            ],
        }

    def collect(self) -> dict[str, Any]:
        return self.collector.collect()
