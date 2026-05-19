"""RBAC do painel: cargos em MySQL + permissões granulares; cargo `dono` usa bypass_all."""
from __future__ import annotations

from cpa_panel.db.queries import list_permissions_for_cargo

_ADMIN_CODES = frozenset(
    {
        "admin.panel",
        "logs.full",
        "logs.payments",
        "logs.audit",
        "users.view",
        "users.create",
        "users.quota",
        "users.status",
        "roles.manage",
        "recarga.manage",
        "system.control",
        "hosts.block",
    }
)


def compute_rbac(user_row: dict | None) -> dict:
    if not user_row:
        return {"bypass_all": False, "permissions": []}

    bypass = int(user_row.get("cargo_bypass_all") or 0) == 1
    if bypass:
        # Representação estável para o front; bypass ignora checagens no servidor.
        return {"bypass_all": True, "permissions": ["*"]}

    cid = user_row.get("cargo_id")
    if cid is None:
        return {"bypass_all": False, "permissions": []}

    codes = list_permissions_for_cargo(int(cid))
    return {"bypass_all": False, "permissions": sorted(set(codes))}


def has_admin_area_access(rbac: dict) -> bool:
    if rbac.get("bypass_all"):
        return True
    perms = set(rbac.get("permissions") or [])
    if perms & _ADMIN_CODES:
        return True
    return False


def has_perm(rbac: dict, code: str) -> bool:
    if rbac.get("bypass_all"):
        return True
    perms = rbac.get("permissions") or []
    if "*" in perms:
        return True
    return code in perms


def require_perm(rbac: dict, code: str) -> None:
    if has_perm(rbac, code):
        return
    raise PermissionError("Sem permissão para esta ação")


def can_view_own_proxy_logs(user_row: dict | None, rbac: dict) -> bool:
    """Histórico de acessos da própria conta (`/api/me/logs`), sem `logs.full` do admin."""
    if rbac.get("bypass_all"):
        return True
    if has_perm(rbac, "logs.full"):
        return True
    if has_perm(rbac, "logs.self"):
        return True
    # Legado: conta sem cargo_id no banco — mantém acesso ao próprio histórico.
    if user_row is not None and user_row.get("cargo_id") is None:
        return True
    return False


def admin_block_for_me(user_row: dict | None) -> dict:
    rbac = compute_rbac(user_row)
    return {
        "has_access": has_admin_area_access(rbac),
        "bypass_all": bool(rbac.get("bypass_all")),
        "cargo_slug": user_row.get("cargo_slug") if user_row else None,
        "cargo_nome": user_row.get("cargo_nome") if user_row else None,
        "permissions": rbac.get("permissions") or [],
        "socio_panel": has_perm(rbac, "socio.panel"),
        "socio_relatorio": has_perm(rbac, "socio.relatorio"),
        "access_proxy_logs": can_view_own_proxy_logs(user_row, rbac),
    }
