"""
Login somente para administradores (painel_admin_users).

Sub-usuários da proxy autenticam via API DataImpulse — ver app.service.login.intentificar_painel.
"""

from werkzeug.security import check_password_hash

from db._db_helpers import fechar_conexao
from db.conexao import conexao


def login_admin(username: str, password: str) -> dict:
    """
    Login da área administrativa (tabela painel_admin_users + cargo).
    Valida senha com hash werkzeug (pbkdf2/bcrypt).
    """
    conn = None
    cursor = None
    user = (username or "").strip()
    if not user or not password:
        return {"status": False, "message": "Usuário e senha são obrigatórios"}

    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT u.id, u.username, u.password_hash, u.nome, u.email, u.ativo,
                   c.id AS cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome,
                   c.bypass_all AS cargo_bypass_all
            FROM painel_admin_users u
            INNER JOIN painel_cargos c ON c.id = u.cargo_id
            WHERE u.username = %s AND u.ativo = 1
            LIMIT 1
            """,
            (user,),
        )
        row = cursor.fetchone()
        if not row:
            return {"status": False, "message": "Usuário ou senha inválidos"}

        if not check_password_hash(row.get("password_hash") or "", password):
            return {"status": False, "message": "Usuário ou senha inválidos"}

        cursor.execute(
            "UPDATE painel_admin_users SET ultimo_login_at = CURRENT_TIMESTAMP(3) WHERE id = %s",
            (row["id"],),
        )
        conn.commit()

        row.pop("password_hash", None)
        return {
            "status": True,
            "message": "Login administrativo realizado",
            "user": row,
        }
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro no login admin: {e}"}
    finally:
        fechar_conexao(conn, cursor)
