from __future__ import annotations

import re

from cpa_panel.db.queries import get_user_for_auth, get_users
from cpa_panel.gateway_ports import is_allowed_port

_AT_STYLE = re.compile(r"^([^:]+):(\d+)@([^:]+):(.*)$", re.DOTALL)


def parse_porta_usuario_senha(credential: str) -> tuple[int, str, str]:
    """
    Credencial no formato host:porta:usuario:senha ou host:porta@usuario:senha.
    O host não é validado contra o banco (apenas não pode ser vazio).
    No formato com dois-pontos, usa split com limite para permitir ':' na senha.
    """
    raw = credential.strip()
    if not raw:
        raise ValueError("Informe sua credencial")

    m = _AT_STYLE.match(raw)
    if m:
        host, porta_s, username, senha = m.group(1).strip(), m.group(2).strip(), m.group(3).strip(), m.group(4)
        if not host:
            raise ValueError("Host obrigatório no início da credencial")
        if not porta_s or not username:
            raise ValueError("Porta e usuário são obrigatórios")
        try:
            porta = int(porta_s)
        except ValueError as e:
            raise ValueError("Porta inválida") from e
        if not is_allowed_port(porta):
            raise ValueError("Porta deve ser 823 (proxy HTTP) ou 824 (proxy SOCKS5)")
        return porta, username, senha.strip()

    parts = raw.split(":", 3)
    if len(parts) != 4:
        raise ValueError(
            "Use host:porta:usuario:senha ou host:porta@usuario:senha "
            "(ex.: proxy.cpaproxys.shop:823:user:senha)"
        )
    host, porta_s, username, senha = parts
    host = host.strip()
    if not host:
        raise ValueError("Host obrigatório no início da credencial")
    username = username.strip()
    senha = senha.strip()
    if not porta_s or not username:
        raise ValueError("Porta e usuário são obrigatórios")
    try:
        porta = int(porta_s.strip())
    except ValueError as e:
        raise ValueError("Porta inválida") from e
    if not is_allowed_port(porta):
        raise ValueError("Porta deve ser 823 (proxy HTTP) ou 824 (proxy SOCKS5)")
    return porta, username, senha


def authenticate_port_user_pass(porta: int, username: str, senha: str) -> dict:
    user = get_user_for_auth(username) or get_users(username)
    if not user:
        raise PermissionError("Credenciais inválidas")
    if user.get("senha") != senha:
        raise PermissionError("Credenciais inválidas")
    if int(user.get("status", 0)) != 1:
        raise PermissionError("Usuário inativo ou bloqueado")
    db_porta = user.get("porta")
    if db_porta is None:
        raise PermissionError("Porta não configurada para este usuário")
    if int(db_porta) != int(porta):
        raise PermissionError("Porta não corresponde ao usuário")
    return user


def user_to_dashboard(user: dict) -> dict:
    """Limite em bytes igual ao gateway (main.check_limit): limite_gb * 10^9."""
    # Normaliza chaves aqui também: evita KeyError quando o driver MySQL devolve casing
    # diferente ou um Row/Mapping que não passou pelo normalizador das queries.
    sm = user if isinstance(user, dict) else dict(user)
    user = {
        (k.decode("utf-8", "replace").lower() if isinstance(k, bytes) else str(k).lower()): v
        for k, v in sm.items()
    }

    usado = int(user.get("usado_bytes") or 0)
    limite_gb = float(user.get("limite_gb") or 0)
    limite_bytes = int(limite_gb * 1000 * 1000 * 1000)
    mb_usados = round(usado / (1000**2), 4)
    gb_usados = round(usado / (1000**3), 6)
    if limite_bytes > 0:
        pct_uso = min(100.0, round(100.0 * usado / limite_bytes, 2))
    else:
        pct_uso = 0.0
    pais_raw = user.get("pais_id")
    pais_id: int | None
    try:
        pais_id = int(pais_raw) if pais_raw is not None else None
    except (TypeError, ValueError):
        pais_id = None

    nome_pais = user.get("pais_nome")

    try:
        if user.get("threads") is not None:
            threads_out = int(user.get("threads"))
        else:
            threads_out = 1800
    except (TypeError, ValueError):
        threads_out = 1800
    if threads_out < 1:
        threads_out = 1800
    if threads_out > 10_000_000:
        threads_out = 10_000_000

    uname_raw = user.get("username")
    porta_raw = user.get("porta")
    if uname_raw is None or porta_raw is None:
        raise ValueError("username ou porta ausentes nos dados da conta.")

    out = {
        "username": str(uname_raw),
        "porta": int(porta_raw),
        "threads": threads_out,
        # Só o próprio usuário autenticado recebe isso em /api/me (JWT já prova posse da conta).
        "senha": str(user.get("senha") or ""),
        "usado_bytes": usado,
        "limite_gb": limite_gb,
        "mb_usados": mb_usados,
        "gb_usados": gb_usados,
        "limite_bytes": limite_bytes,
        "pct_uso": pct_uso,
        "status": int(user.get("status", 0)),
        "pais_id": pais_id,
        "pais_nome": nome_pais if nome_pais else None,
        "cargo_slug": user.get("cargo_slug"),
        "cargo_nome": user.get("cargo_nome"),
    }
    return out
