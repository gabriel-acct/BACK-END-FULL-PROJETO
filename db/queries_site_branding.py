"""Configuração de marca do site (nome, logo, textos)."""

from db._db_helpers import fechar_conexao
from db.conexao import conexao

DEFAULT_BRANDING = {
    "site_name": "Proxy Private",
    "site_tagline": "Painel de proxy privado",
    "login_title": "Entrar na conta",
    "login_subtitle": None,
    "footer_text": None,
    "support_email": None,
    "support_whatsapp": None,
    "logo_url": None,
    "logo_filename": None,
    "favicon_filename": None,
}


def _normalize_logo_url(val) -> str | None:
    if val is None:
        return None
    url = str(val).strip()
    if not url:
        return None
    if not url.lower().startswith(("http://", "https://")):
        return None
    return url[:512]


def _row_to_public(row: dict) -> dict:
    return {
        "site_name": row.get("site_name") or DEFAULT_BRANDING["site_name"],
        "site_tagline": row.get("site_tagline"),
        "login_title": row.get("login_title") or DEFAULT_BRANDING["login_title"],
        "login_subtitle": row.get("login_subtitle"),
        "footer_text": row.get("footer_text"),
        "support_email": row.get("support_email"),
        "support_whatsapp": row.get("support_whatsapp"),
        "logo_url": row.get("logo_url"),
        "logo_filename": row.get("logo_filename"),
        "favicon_filename": row.get("favicon_filename"),
        "updated_at": row.get("updated_at"),
    }


def get_site_branding() -> dict:
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
            FROM painel_site_branding
            WHERE id = 1
            LIMIT 1
            """,
        )
        row = cursor.fetchone()
        if not row:
            return {
                "status": True,
                "message": "Usando valores padrão",
                "branding": dict(DEFAULT_BRANDING),
            }
        return {
            "status": True,
            "message": "Configuração carregada",
            "branding": _row_to_public(row),
        }
    except Exception as e:
        err = str(e)
        if "1146" in err or "doesn't exist" in err.lower():
            return {
                "status": True,
                "message": "Tabela de branding não aplicada — usando padrão",
                "branding": dict(DEFAULT_BRANDING),
            }
        return {"status": False, "message": f"Erro ao carregar branding: {e}"}
    finally:
        fechar_conexao(conn, cursor)


_ALLOWED_PATCH = frozenset({
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


def update_site_branding(fields: dict, *, updated_by: str | None = None) -> dict:
    if not fields:
        return {"status": False, "message": "Nenhum campo para atualizar"}

    parts: list[str] = []
    params: list = []

    for key, val in fields.items():
        if key not in _ALLOWED_PATCH:
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
                return {
                    "status": False,
                    "message": "URL do logo inválida. Use http:// ou https://",
                }
            parts.append("logo_url = %s")
            params.append(normalized)
            if normalized:
                parts.append("logo_filename = NULL")
            continue
        if val is None or (isinstance(val, str) and not val.strip()):
            parts.append(f"{key} = NULL")
        else:
            max_len = 512 if key in ("login_subtitle", "footer_text") else 255
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
    params.append((updated_by or "system")[:64])
    params.append(1)

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE painel_site_branding SET {', '.join(parts)} WHERE id = %s",
            tuple(params),
        )
        if cursor.rowcount == 0:
            cursor.execute(
                """
                INSERT INTO painel_site_branding (id, site_name, updated_by)
                VALUES (1, %s, %s)
                """,
                (fields.get("site_name") or DEFAULT_BRANDING["site_name"], updated_by or "system"),
            )
        conn.commit()
        return get_site_branding()
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return {"status": False, "message": f"Erro ao salvar branding: {e}"}
    finally:
        fechar_conexao(conn, cursor)
