"""Normalização de hostnames/IPs para listas do painel (dashboard e pedidos sócio)."""
from __future__ import annotations

import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$"
)


def _normalize_domain(raw: str) -> str:
    t = (raw or "").strip().lower().rstrip(".")
    if not t or len(t) > 253:
        raise ValueError("domínio inválido")
    if not _DOMAIN_RE.match(t):
        raise ValueError("domínio inválido (use apenas letras, números, pontos e hífen)")
    return t


def normalize_dashboard_host_value(raw: str) -> str:
    """Domínio ou endereço IP para listas exibidas no painel do cliente."""
    t = (raw or "").strip().lower().rstrip(".")
    if not t:
        raise ValueError("host vazio")
    if len(t) > 253:
        raise ValueError("host muito longo (máx. 253 caracteres)")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    return _normalize_domain(t)
