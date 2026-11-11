"""Typed packet metadata for the conservative iptables evaluator."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


SUPPORTED_PROTOCOLS = {
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "ipv6-icmp",
    "sctp",
    "udplite",
}


SUPPORTED_CONNECTION_STATES = {
    "INVALID",
    "NEW",
    "ESTABLISHED",
    "RELATED",
    "UNTRACKED",
    "SNAT",
    "DNAT",
}


SUPPORTED_TCP_FLAGS = {
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
    "ECE",
    "CWR",
}


@dataclass(frozen=True, slots=True)
class Packet:
    """Packet tuple as observed at the selected filter hook.

    Addresses are validated and canonicalised. The evaluator does not include
    packet addresses in its result or execution trace.
    """

    family: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    input_interface: str | None = None
    output_interface: str | None = None
    connection_state: str | None = None
    tcp_flags: frozenset[str] | None = None
    is_non_initial_fragment: bool | None = None

    def __post_init__(self) -> None:
        if self.family not in {"ipv4", "ipv6"}:
            raise ValueError("family tem de ser 'ipv4' ou 'ipv6'.")

        expected_version = 4 if self.family == "ipv4" else 6

        for field_name in ("source_ip", "destination_ip"):
            value = getattr(self, field_name)
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"{field_name} não é um endereço IP válido.") from exc

            if address.version != expected_version:
                raise ValueError(
                    f"{field_name} não corresponde à família {self.family}."
                )

            object.__setattr__(self, field_name, str(address))

        protocol = self.protocol.lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError("Protocolo do pacote não suportado.")
        if self.family == "ipv4" and protocol in {"icmpv6", "ipv6-icmp"}:
            raise ValueError("ICMPv6 não é válido num pacote IPv4.")
        if self.family == "ipv6" and protocol == "icmp":
            raise ValueError("ICMPv4 não é válido num pacote IPv6.")
        object.__setattr__(self, "protocol", protocol)

        for field_name in ("source_port", "destination_port"):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 65535
            ):
                raise ValueError(
                    f"{field_name} tem de ser null ou um inteiro entre 1 e 65535."
                )

        if self.connection_state is not None:
            state = self.connection_state.upper()
            if state not in SUPPORTED_CONNECTION_STATES:
                raise ValueError("Estado de ligação não suportado.")
            object.__setattr__(self, "connection_state", state)

        if self.tcp_flags is not None:
            flags = frozenset(flag.upper() for flag in self.tcp_flags)
            if not flags <= SUPPORTED_TCP_FLAGS:
                raise ValueError("O pacote contém uma TCP flag não suportada.")
            object.__setattr__(self, "tcp_flags", flags)

        for field_name in ("input_interface", "output_interface"):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, str) or not value.strip()
            ):
                raise ValueError(f"{field_name} tem de ser null ou texto não vazio.")

        if (
            self.is_non_initial_fragment is not None
            and not isinstance(self.is_non_initial_fragment, bool)
        ):
            raise ValueError("is_non_initial_fragment tem de ser boolean ou null.")
