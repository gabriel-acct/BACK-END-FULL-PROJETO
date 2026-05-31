"""
Dados de administradores (painel_admin_users + cargo + permissões).

Sub-usuários vêm da API DataImpulse (sub_usuarios.py), não deste módulo.
"""

import re

from werkzeug.security import generate_password_hash

from db._db_helpers import fechar_conexao
from db.conexao import conexao

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def get_admin_por_id(user_id: int) -> dict:
    """Administrador por ID com dados do cargo."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT u.id, u.username, u.nome, u.email, u.ativo, u.ultimo_login_at,
                   u.created_at, u.updated_at,
                   CAST(u.limite_gb AS DECIMAL(12, 3)) AS limite_gb,
                   c.id AS cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome,
                   c.bypass_all AS cargo_bypass_all
            FROM painel_admin_users u
            INNER JOIN painel_cargos c ON c.id = u.cargo_id
            WHERE u.id = %s
            LIMIT 1
            """,
            (int(user_id),),
        )
        row = cursor.fetchone()
        if not row:
            return {"status": False, "message": "Administrador não encontrado"}

        return {
            "status": True,
            "message": "Administrador encontrado",
            "user": row,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao buscar administrador: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def get_admin_permissoes(cargo_id: int) -> dict:
    """Lista códigos de permissão do cargo."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT permission_code AS code
            FROM painel_cargo_permissoes
            WHERE cargo_id = %s
            ORDER BY permission_code
            """,
            (int(cargo_id),),
        )
        rows = cursor.fetchall()
        return {
            "status": True,
            "message": "Permissões carregadas",
            "permissions": [r["code"] for r in rows],
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao buscar permissões: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def get_admin_completo(user_id: int) -> dict:
    """Administrador + permissões (sessão / bootstrap admin)."""
    base = get_admin_por_id(user_id)
    if not base["status"]:
        return base

    user = base["user"]
    if int(user.get("cargo_bypass_all") or 0) == 1:
        user["permissions"] = ["*"]
        return {
            "status": True,
            "message": "Administrador encontrado",
            "user": user,
        }

    perms = get_admin_permissoes(user["cargo_id"])
    if not perms["status"]:
        return perms

    user["permissions"] = perms["permissions"]
    return {
        "status": True,
        "message": "Administrador encontrado",
        "user": user,
    }


def admin_has_permission_code(user_row: dict, code: str) -> bool:
    if int(user_row.get("cargo_bypass_all") or 0) == 1:
        return True
    perms = user_row.get("permissions")
    if perms == ["*"]:
        return True
    if isinstance(perms, list):
        return code in perms
    return False


def admin_is_dono(user_row: dict) -> bool:
    """True se o cargo é Dono (único que gerencia contas admin)."""
    if int(user_row.get("cargo_bypass_all") or 0) == 1:
        return True
    return (user_row.get("cargo_slug") or "").strip().lower() == "dono"


def list_admin_users() -> dict:
    """Lista contas administrativas (sem hash de senha)."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT u.id, u.username, u.nome, u.email, u.ativo, u.ultimo_login_at,
                   u.created_at,
                   CAST(u.limite_gb AS DECIMAL(12, 3)) AS limite_gb,
                   c.id AS cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome
            FROM painel_admin_users u
            INNER JOIN painel_cargos c ON c.id = u.cargo_id
            ORDER BY u.created_at DESC, u.id DESC
            """
        )
        rows = cursor.fetchall()
        return {
            "status": True,
            "message": "Administradores listados",
            "users": rows,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao listar administradores: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def list_cargos_assignable_for_admin() -> dict:
    """Cargos que o Dono pode atribuir ao criar administrador (exceto Dono)."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, slug, nome, bypass_all
            FROM painel_cargos
            WHERE slug <> 'dono'
            ORDER BY nome ASC
            """
        )
        rows = cursor.fetchall()
        return {
            "status": True,
            "message": "Cargos disponíveis",
            "cargos": rows,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao listar cargos: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def list_audit_logs(limit: int = 50, offset: int = 0):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return []
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, created_at, actor_username, action, target_type, target_key, detail,
                       ip_address, user_agent
                FROM painel_audit_log
                ORDER BY id DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
        except Exception:
            cursor.execute(
                """
                SELECT id, created_at, actor_username, action, target_type, target_key, detail
                FROM painel_audit_log
                ORDER BY id DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
        rows = cursor.fetchall()
        for r in rows:
            r.setdefault("ip_address", None)
            r.setdefault("user_agent", None)
        return rows
    except Exception:
        return []
    finally:
        fechar_conexao(conn, cursor)


def count_audit_logs() -> int:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return 0
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM painel_audit_log")
        row = cursor.fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0
    finally:
        fechar_conexao(conn, cursor)


def insert_audit_log(
    actor_username: str,
    action: str,
    target_type: str | None = None,
    target_key: str | None = None,
    detail: str | None = None,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO painel_audit_log
                  (actor_username, action, target_type, target_key, detail, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    actor_username,
                    action,
                    target_type,
                    target_key,
                    detail,
                    (ip_address or "").strip()[:45] or None,
                    (user_agent or "").strip()[:255] or None,
                ),
            )
        except Exception:
            cursor.execute(
                """
                INSERT INTO painel_audit_log (actor_username, action, target_type, target_key, detail)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (actor_username, action, target_type, target_key, detail),
            )
        conn.commit()
        return {"status": True, "message": "Log registrado", "id": cursor.lastrowid}
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro ao registrar auditoria: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def get_admin_gb_pool_summary(admin_username: str) -> dict:
    """Pool de GB do revendedor (sócio): limite na conta admin vs soma nos sub-usuários locais."""
    from db.queires import sum_subusers_limite_gb_criado_por

    admin_username = (admin_username or "").strip()
    limite = 0.0
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"limite_gb": 0.0, "alocado_gb": 0.0, "disponivel_gb": 0.0}
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT CAST(limite_gb AS DECIMAL(12, 3)) AS limite_gb
            FROM painel_admin_users
            WHERE username = %s
            LIMIT 1
            """,
            (admin_username,),
        )
        row = cursor.fetchone()
        if row and row.get("limite_gb") is not None:
            limite = float(row["limite_gb"])
    except Exception:
        limite = 0.0
    finally:
        fechar_conexao(conn, cursor)

    alocado = sum_subusers_limite_gb_criado_por(admin_username)
    disp = max(0.0, limite - alocado)
    return {
        "limite_gb": round(limite, 6),
        "alocado_gb": round(alocado, 6),
        "disponivel_gb": round(disp, 6),
    }


def update_admin_limite_gb(user_id: int, limite_gb: float) -> dict:
    if limite_gb < 0 or limite_gb > 1_000_000:
        return {"status": False, "message": "limite_gb fora do intervalo permitido"}

    base = get_admin_por_id(user_id)
    if not base["status"]:
        return base
    row = base["user"]
    slug = str(row.get("cargo_slug") or "").strip().lower()
    if slug != "socio":
        return {"status": False, "message": "limite_gb só se aplica a contas com cargo Sócio / Revendedor"}

    alocado = 0.0
    from db.queires import sum_subusers_limite_gb_criado_por

    alocado = sum_subusers_limite_gb_criado_por(str(row.get("username") or ""))
    if float(limite_gb) + 1e-9 < alocado:
        return {
            "status": False,
            "message": f"limite_gb não pode ser menor que o já alocado aos sub-usuários ({alocado:g} GB).",
        }

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE painel_admin_users SET limite_gb = %s WHERE id = %s",
            (float(limite_gb), int(user_id)),
        )
        conn.commit()
        return {"status": True, "message": "Pool de GB atualizado"}
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": str(e)[:300]}
    finally:
        fechar_conexao(conn, cursor)


def create_admin_user(
    *,
    username: str,
    password: str,
    nome: str,
    email: str | None,
    cargo_id: int,
    actor_username: str,
    limite_gb: float | None = None,
) -> dict:
    """Cria conta em painel_admin_users (somente cargo diferente de Dono)."""
    user = (username or "").strip()
    nome_v = (nome or "").strip()
    email_v = (email or "").strip() or None

    if not _USERNAME_RE.match(user):
        return {
            "status": False,
            "message": "Usuário inválido (3–64 caracteres: letras, números, . _ -)",
        }
    if not password or len(password) < 8:
        return {"status": False, "message": "Senha deve ter no mínimo 8 caracteres"}
    if not nome_v:
        return {"status": False, "message": "Nome é obrigatório"}

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, slug FROM painel_cargos WHERE id = %s LIMIT 1",
            (int(cargo_id),),
        )
        cargo = cursor.fetchone()
        if not cargo:
            return {"status": False, "message": "Cargo não encontrado"}
        if cargo["slug"] == "dono":
            return {
                "status": False,
                "message": "Não é permitido criar outro usuário com cargo Dono",
            }

        pool_gb = None
        if cargo["slug"] == "socio":
            if limite_gb is None:
                return {
                    "status": False,
                    "message": "Para cargo Sócio / Revendedor, informe limite_gb (pool de GB).",
                }
            try:
                pool_gb = float(limite_gb)
            except (TypeError, ValueError):
                return {"status": False, "message": "limite_gb inválido"}
            if pool_gb <= 0:
                return {"status": False, "message": "limite_gb deve ser maior que zero para revendedor"}

        cursor.execute(
            "SELECT id FROM painel_admin_users WHERE username = %s LIMIT 1",
            (user,),
        )
        if cursor.fetchone():
            return {"status": False, "message": "Nome de usuário já está em uso"}

        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                """
                INSERT INTO painel_admin_users
                  (username, password_hash, nome, email, cargo_id, ativo, limite_gb)
                VALUES (%s, %s, %s, %s, %s, 1, %s)
                """,
                (user, password_hash, nome_v, email_v, int(cargo_id), pool_gb),
            )
        except Exception:
            cursor.execute(
                """
                INSERT INTO painel_admin_users (username, password_hash, nome, email, cargo_id, ativo)
                VALUES (%s, %s, %s, %s, %s, 1)
                """,
                (user, password_hash, nome_v, email_v, int(cargo_id)),
            )
            if cargo["slug"] == "socio":
                return {
                    "status": False,
                    "message": "Execute a migração sql/010_painel_admin_socio_revenda.sql no banco painel_reseller.",
                }
        new_id = cursor.lastrowid
        conn.commit()

        insert_audit_log(
            actor_username,
            "admin_user.create",
            "admin_user",
            user,
            f"Administrador criado (id={new_id}, cargo={cargo['slug']})",
        )

        return {
            "status": True,
            "message": "Administrador criado com sucesso",
            "id": int(new_id),
        }
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro ao criar administrador: {e}"}
    finally:
        fechar_conexao(conn, cursor)
