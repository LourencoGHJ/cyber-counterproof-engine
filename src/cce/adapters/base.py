"""Contrato comum para adaptadores de firewall."""

from abc import ABC, abstractmethod
from typing import Any


class FirewallAdapter(ABC):
    """Interface comum para recolha read-only de firewalls."""

    adapter_id: str
    platform: str

    @abstractmethod
    def probe(self) -> dict[str, Any]:
        """Verifica disponibilidade sem consultar ou alterar regras."""
        raise NotImplementedError

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Recolhe e analisa evidência através do adaptador."""
        raise NotImplementedError
