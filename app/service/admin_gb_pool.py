"""Pool de GB para administradores com cargo «socio» (revenda no Proxy Private)."""
from __future__ import annotations


def admin_uses_gb_pool(user_row: dict | None) -> bool:
    if not user_row:
        return False
    if int(user_row.get("cargo_bypass_all") or 0) == 1:
        return False
    slug = str(user_row.get("cargo_slug") or "").strip().lower()
    return slug == "socio"


def assert_can_allocate_subuser_gb(
    user_row: dict | None,
    *,
    traffic_gb: float,
    quantity: int = 1,
) -> tuple[bool, str | None]:
    """
    Dono/administrador com bypass: sempre OK.
    Cargo socio: exige limite_gb no pool e soma dos filhos <= limite.
    """
    if not admin_uses_gb_pool(user_row):
        return True, None

    from db.queries_usuario import get_admin_gb_pool_summary

    username = str(user_row.get("username") or "").strip()
    if not username:
        return False, "Usuário administrativo inválido."

    try:
        qty = int(quantity)
    except (TypeError, ValueError):
        qty = 1
    if qty < 1:
        return False, "quantity inválida"

    try:
        each = float(traffic_gb)
    except (TypeError, ValueError):
        return False, "traffic_gb inválido"
    if each <= 0:
        return False, "Informe GB maior que zero"

    need = each * qty
    pool = get_admin_gb_pool_summary(username)
    limite = float(pool.get("limite_gb") or 0)
    if limite <= 0:
        return (
            False,
            "Seu pool de GB não está configurado. O Dono deve definir o limite na criação da sua conta.",
        )
    disp = float(pool.get("disponivel_gb") or 0)
    if need > disp + 1e-9:
        return (
            False,
            f"Cota insuficiente no pool: precisa de {need:g} GB ({qty} × {each:g} GB), "
            f"disponível ~{max(0.0, disp):.4f} GB.",
        )
    return True, None
