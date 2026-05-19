"""Autenticação CPA (usuarios_proxy) para login unificado."""

from __future__ import annotations

from flask import current_app

from cpa_panel.security import issue_token as cpa_issue_token
from cpa_panel.services.auth_service import authenticate_port_user_pass, parse_porta_usuario_senha


def login_cpa_por_credencial(credential: str) -> dict:
    """
    Valida credencial no banco CPA. Retorna dict com status False se não for conta CPA.
    """
    try:
        porta, username, senha = parse_porta_usuario_senha(credential)
        user = authenticate_port_user_pass(porta, username, senha)
    except ValueError:
        return {"status": False}
    except PermissionError:
        return {"status": False}

    token = cpa_issue_token(str(user["username"]), int(user["porta"]))

    cargo = (user.get("cargo_slug") or "cliente").strip() or "cliente"
    return {
        "status": True,
        "message": "Login CPA realizado com sucesso",
        "product": "cpa",
        "role": cargo,
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "username": str(user["username"]),
        "porta": int(user["porta"]),
    }
