"""Marca do revendedor (sócio) — exibida aos sub-usuários criados por ele."""

from db._db_helpers import fechar_conexao
from db.conexao import conexao
from db.queries_site_branding import DEFAULT_BRANDING, _normalize_logo_url

SOCIO_BRANDING_FIELDS = frozenset({
    "site_name",
    "site_tagline",
    "login_title",
    "login_subtitle",
    "footer_text",
    "support_email",
    "support_whatsapp",
    "logo_url",
    "logo_filename",
    "favicon_filename",
})


def _row_to_dict(row: dict | None) -> dict:
    if not row:
        return {}
    return {
        "site_name": row.get("site_name"),
        "site_tagline": row.get("site_tagline"),
        "login_title": row.get("login_title"),
        "login_subtitle": row.get("login_subtitle"),
        "footer_text": row.get("footer_text"),
        "support_email": row.get("support_email"),
        "support_whatsapp": row.get("support_whatsapp"),
        "logo_url": row.get("logo_url"),
        "logo_filename": row.get("logo_filename"),
        "favicon_filename": row.get("favicon_filename"),
        "updated_at": row.get("updated_at"),
        "updated_by": row.get("updated_by"),
    }


def get_socio_branding(admin_username: str) -> dict:
    admin_username = (admin_username or "").strip()
    if not admin_username:
        return {"status": False, "message": "Revendedor inválido"}

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT site_name, site_tagline, login_title, login_subtitle, footer_text,
                   support_email, support_whatsapp, logo_url, logo_filename, favicon_filename,
                   updated_at, updated_by
            FROM painel_socio_branding
            WHERE admin_username = %s
            LIMIT 1
            """,
            (admin_username,),
        )
        row = cursor.fetchone()
        return {
            "status": True,
            "message": "Configuração carregada" if row else "Sem personalização — usando padrão do site",
            "branding": _row_to_dict(row),
            "admin_username": admin_username,
        }
    except Exception as e:
        err = str(e)
        if "1146" in err or "doesn't exist" in err.lower():
            return {
                "status": True,
                "message": "Execute sql/011_socio_branding_audit.sql",
                "branding": {},
                "admin_username": admin_username,
            }
        return {"status": False, "message": f"Erro ao carregar marca do revendedor: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def update_socio_branding(admin_username: str, fields: dict, *, updated_by: str | None = None) -> dict:
    admin_username = (admin_username or "").strip()
    if not admin_username:
        return {"status": False, "message": "Revendedor inválido"}
    if not fields:
        return {"status": False, "message": "Nenhum campo para atualizar"}

    parts: list[str] = []
    params: list = []

    for key, val in fields.items():
        if key not in SOCIO_BRANDING_FIELDS:
            continue
        if key == "site_name":
            name = (str(val).strip() if val is not None else "")[:120]
            if not name:
                return {"status": False, "message": "Nome do site não pode ser vazio"}
            parts.append("site_name = %s")
            params.append(name)
            continue
        if key == "logo_url":
            normalized = _normalize_logo_url(val)
            if val is not None and str(val).strip() and normalized is None:
                return {"status": False, "message": "URL do logo inválida. Use http:// ou https://"}
            parts.append("logo_url = %s")
            params.append(normalized)
            if normalized:
                parts.append("logo_filename = NULL")
            continue
        if val is None or (isinstance(val, str) and not val.strip()):
            parts.append(f"{key} = NULL")
        else:
            max_len = 512 if key in ("login_subtitle", "footer_text", "logo_url") else 255
            if key in ("support_email",):
                max_len = 190
            if key in ("support_whatsapp",):
                max_len = 40
            if key in ("logo_filename", "favicon_filename"):
                max_len = 120
            parts.append(f"{key} = %s")
            params.append(str(val).strip()[:max_len])

    if not parts:
        return {"status": False, "message": "Nenhum campo válido"}

    parts.append("updated_by = %s")
    params.append((updated_by or admin_username)[:64])

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}
        cursor = conn.cursor()
        params_update = list(params)
        params_update.append(admin_username)
        cursor.execute(
            f"UPDATE painel_socio_branding SET {', '.join(parts)} WHERE admin_username = %s",
            tuple(params_update),
        )
        if cursor.rowcount == 0:
            cols = ["admin_username"] + [p.split(" = ")[0] for p in parts]
            placeholders = ["%s"] * len(cols)
            vals = [admin_username] + params[:-1]
            cursor.execute(
                f"INSERT INTO painel_socio_branding ({', '.join(cols)}) VALUES ({', '.join(placeholders)})",
                tuple(vals),
            )
        conn.commit()
        return get_socio_branding(admin_username)
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro ao salvar marca: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def socio_has_custom_branding(admin_username: str) -> bool:
    data = get_socio_branding(admin_username)
    if not data.get("status"):
        return False
    b = data.get("branding") or {}
    return bool(
        (b.get("site_name") or "").strip()
        or (b.get("logo_url") or "").strip()
        or (b.get("logo_filename") or "").strip()
        or (b.get("favicon_filename") or "").strip()
    )
