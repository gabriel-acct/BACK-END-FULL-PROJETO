"""Portas do gateway (alinhado a sistema-proxy-rotativa/main.py)."""
from __future__ import annotations

PORT_HTTP = 823
PORT_SOCKS5 = 824
ALLOWED_PORTS: frozenset[int] = frozenset({PORT_HTTP, PORT_SOCKS5})


def is_allowed_port(port: int) -> bool:
    return int(port) in ALLOWED_PORTS
