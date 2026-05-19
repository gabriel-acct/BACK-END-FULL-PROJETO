"""Permite ao Dono do painel Proxy Private (/admin) usar rotas /api/admin (ARE CEO)."""
from __future__ import annotations

from flask import jsonify

from cpa_panel.db import queries


def _synthetic_dono_user(admin_row: dict) -> dict:
    return {
        "username": str(admin_row.get("username") or ""),
        "porta": 823,
        "cargo_bypass_all": 1,
        "cargo_slug": "dono",
        "cargo_nome": admin_row.get("cargo_nome") or "Dono",
        "cargo_id": admin_row.get("cargo_id"),
    }


def ctx_from_private_admin_token(payload: dict) -> tuple[tuple[dict, dict] | None, tuple | None]:
    """
    Valida JWT do painel_admin_users (role=admin) com cargo bypass_all.
    Retorna ((user_row, rbac), None) ou (None, resposta_erro).
    """
    if payload.get("role") != "admin":
        return None, None

    try:
        admin_id = int(payload.get("sub") or 0)
    except (TypeError, ValueError):
        return None, (jsonify(error="Token administrativo inválido"), 401)

    from db.queries_usuario import get_admin_completo

    data = get_admin_completo(admin_id)
    if not data.get("status"):
        return None, (jsonify(error="Administrador não encontrado"), 401)

    admin_row = data["user"]
    if int(admin_row.get("cargo_bypass_all") or 0) != 1:
        return None, (jsonify(error="Acesso administrativo negado"), 403)

    username = str(admin_row.get("username") or "").strip()
    cpa_user = None
    if username:
        cpa_user = queries.get_user_for_auth(username) or queries.get_users(username)

    # Dono no painel Private sempre tem bypass na ARE CEO (cargo CPA pode ser diferente).
    rbac = {"bypass_all": True, "permissions": ["*"]}
    if cpa_user:
        return (cpa_user, rbac), None

    return (_synthetic_dono_user(admin_row), rbac), None
