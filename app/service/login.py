"""
Autenticação unificada via credencial host:porta:usuario:senha.

intentificar_painel identifica admin (banco) ou sub-usuário (API DataImpulse).
"""

from app.service.cpa_login import login_cpa_por_credencial
from app.service.format import parse_porta_usuario_senha
from app.service.segury import issue_admin_token
from app.service.sub_usuarios import authenticate_subuser_by_login
from db.queries_login import login_admin
from db.queries_usuario import get_admin_completo


def _format_admin_user_for_api(row: dict) -> dict:
    perms = row.get("permissions") or []
    bypass = bool(int(row.get("cargo_bypass_all") or 0))
    return {
        "id": row["id"],
        "username": row["username"],
        "nome": row["nome"],
        "email": row.get("email"),
        "cargo": {
            "id": row["cargo_id"],
            "slug": row["cargo_slug"],
            "nome": row["cargo_nome"],
            "bypass_all": bypass,
            "permissions": perms if not bypass else [],
        },
    }


def _login_admin(username: str, password: str) -> dict:
    auth = login_admin(username, password)
    if not auth["status"]:
        return auth

    admin_id = auth["user"]["id"]
    completo = get_admin_completo(admin_id)
    if not completo["status"]:
        return completo

    token = issue_admin_token(int(admin_id))
    return {
        "status": True,
        "message": auth["message"],
        "role": "admin",
        "token": token,
        "user": _format_admin_user_for_api(completo["user"]),
    }


def _login_subusuario(login: str, password: str) -> dict:
    result = authenticate_subuser_by_login(login, password)
    if not result["status"]:
        api_msg = str(result.get("message") or "")
        if "token" in api_msg.lower() and "expired" in api_msg.lower():
            return {
                "status": False,
                "message": (
                    "Não foi possível conectar à API da proxy. "
                    "Verifique LOGIN/PASSWORD no .env e tente novamente."
                ),
            }
    return result


def intentificar_painel(credential: str) -> dict:
    """
    Login único do painel: admin (banco) ou sub-usuário (API).
    Credencial: host:porta:usuario:senha ou host:porta@usuario:senha.
    """
    try:
        _porta, username, senha = parse_porta_usuario_senha(credential)

        admin = _login_admin(username, senha)
        if admin["status"]:
            admin["product"] = "private"
            return admin

        cpa = login_cpa_por_credencial(credential)
        if cpa.get("status"):
            return cpa

        sub = _login_subusuario(username, senha)
        if sub.get("status"):
            sub["product"] = "private"
        return sub
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao identificar painel: {e}",
        }
