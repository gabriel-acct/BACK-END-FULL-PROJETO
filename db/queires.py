"""
Queries do token da API (DataImpulse).

Login admin → db/queries_login.py
Dados admin → db/queries_usuario.py
"""

from db._db_helpers import fechar_conexao
from db.conexao import conexao

from db.queries_login import login_admin  # noqa: F401
from db.queries_usuario import (  # noqa: F401
    get_admin_completo,
    get_admin_por_id,
    get_admin_permissoes,
)

login_admin_db = login_admin


def insert_token(token: str):
    conn = None
    cursor = None

    try:
        conn = conexao()

        if conn is None:
            return {
                "status": False,
                "message": "Erro ao conectar no banco de dados"
            }

        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO proxys_private (token) VALUES (%s)",
            (token,)
        )

        conn.commit()

        return {
            "status": True,
            "message": "Token inserted successfully"
        }

    except Exception as e:
        if conn:
            conn.rollback()

        print(f"Error inserting token: {e}")

        return {
            "status": False,
            "message": f"Error inserting token: {e}"
        }

    finally:
        fechar_conexao(conn, cursor)


def get_token():
    conn = None
    cursor = None

    try:
        conn = conexao()
        cursor = conn.cursor()
        cursor.execute("SELECT TOKEN FROM proxys_private ORDER BY id DESC LIMIT 1")
        token = cursor.fetchone()
        return {
            "status": True,
            "message": "Token retrieved successfully",
            "token": token[0]
        }
    except Exception as e:
        print(f"Error getting token: {e}")
        return {
            "status": False,
            "message": f"Error getting token: {e}",
            "token": None
        }
    finally:
        fechar_conexao(conn, cursor)


def update_token(token: str):
    """Atualiza o token mais recente (mesmo registro que get_token lê)."""
    conn = None
    cursor = None

    try:
        conn = conexao()

        if conn is None:
            return {
                "status": False,
                "message": "Erro ao conectar no banco de dados",
            }

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM proxys_private ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            cursor.execute("INSERT INTO proxys_private (token) VALUES (%s)", (token,))
        else:
            cursor.execute(
                "UPDATE proxys_private SET token = %s WHERE id = %s",
                (token, row["id"]),
            )
        conn.commit()
        return {
            "status": True,
            "message": "Token updated successfully",
        }
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error updating token: {e}")
        return {
            "status": False,
            "message": f"Error updating token: {e}",
        }
    finally:
        fechar_conexao(conn, cursor)

def _normalize_hostname(hostname: str) -> str:
    host = (hostname or "").strip().lower()
    if not host or len(host) > 253:
        raise ValueError("Hostname inválido")
    return host


def list_proxy_hosts(*, only_active: bool = False) -> dict:
    """Lista hosts do dashboard (admin: todos; cliente: só ativos)."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        sql = """
            SELECT id, hostname, sort_order, ativo, atualizado_em
            FROM painel_dashboard_proxy_hosts
        """
        if only_active:
            sql += " WHERE ativo = 1"
        sql += " ORDER BY sort_order ASC, hostname ASC"
        cursor.execute(sql)
        rows = cursor.fetchall()
        return {
            "status": True,
            "message": "Hosts carregados",
            "hosts": rows,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao listar hosts: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def get_proxy_hostnames_for_dashboard() -> dict:
    """Somente hostnames ativos para o seletor do painel cliente."""
    listed = list_proxy_hosts(only_active=True)
    if not listed["status"]:
        return listed
    hostnames = [r["hostname"] for r in listed["hosts"]]
    return {
        "status": True,
        "message": "Hosts do dashboard carregados",
        "hosts": hostnames,
    }


def resolve_proxy_hosts_selection(hostnames: list | None) -> dict:
    """
    Valida host(s) escolhido(s) para credenciais (somente ativos no banco).
    Aceita lista; se vazia, usa o primeiro host ativo.
    """
    listed = list_proxy_hosts(only_active=True)
    if not listed["status"]:
        return listed
    allowed = [r["hostname"] for r in listed.get("hosts") or []]
    if not allowed:
        return {
            "status": False,
            "message": "Nenhum host ativo cadastrado. Cadastre em Hosts do painel.",
        }

    if not hostnames:
        return {
            "status": True,
            "message": "Usando primeiro host ativo",
            "hosts": [allowed[0]],
        }

    selected: list[str] = []
    seen: set[str] = set()
    for raw in hostnames:
        try:
            host = _normalize_hostname(str(raw))
        except ValueError:
            return {"status": False, "message": f"Hostname inválido: {raw}"}
        if host not in allowed:
            return {
                "status": False,
                "message": f"Host não disponível ou inativo: {host}",
            }
        if host not in seen:
            seen.add(host)
            selected.append(host)

    if not selected:
        return {
            "status": False,
            "message": "Selecione pelo menos um host ativo",
        }

    return {
        "status": True,
        "message": "Hosts validados",
        "hosts": selected,
    }


def insert_proxy_host(hostname: str, sort_order: int = 0) -> dict:
    conn = None
    cursor = None
    try:
        host = _normalize_hostname(hostname)
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO painel_dashboard_proxy_hosts (hostname, sort_order, ativo)
            VALUES (%s, %s, 1)
            """,
            (host, int(sort_order)),
        )
        conn.commit()
        return {
            "status": True,
            "message": "Host cadastrado",
            "id": cursor.lastrowid,
        }
    except Exception as e:
        if conn:
            conn.rollback()
        msg = str(e)
        if "Duplicate" in msg or "uq_painel_dashboard" in msg:
            return {"status": False, "message": "Este hostname já está cadastrado"}
        return {"status": False, "message": f"Erro ao cadastrar host: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def update_proxy_host(
    host_id: int,
    *,
    hostname: str | None = None,
    sort_order: int | None = None,
    ativo: int | None = None,
) -> dict:
    conn = None
    cursor = None
    try:
        fields = []
        params: list = []
        if hostname is not None:
            fields.append("hostname = %s")
            params.append(_normalize_hostname(hostname))
        if sort_order is not None:
            fields.append("sort_order = %s")
            params.append(int(sort_order))
        if ativo is not None:
            fields.append("ativo = %s")
            params.append(1 if int(ativo) else 0)

        if not fields:
            return {"status": False, "message": "Nada para atualizar"}

        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        params.append(int(host_id))
        cursor.execute(
            f"UPDATE painel_dashboard_proxy_hosts SET {', '.join(fields)} WHERE id = %s",
            tuple(params),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return {"status": False, "message": "Host não encontrado"}
        return {"status": True, "message": "Host atualizado"}
    except Exception as e:
        if conn:
            conn.rollback()
        msg = str(e)
        if "Duplicate" in msg or "uq_painel_dashboard" in msg:
            return {"status": False, "message": "Este hostname já está cadastrado"}
        return {"status": False, "message": f"Erro ao atualizar host: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def delete_proxy_host(host_id: int) -> dict:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM painel_dashboard_proxy_hosts WHERE id = %s",
            (int(host_id),),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return {"status": False, "message": "Host não encontrado"}
        return {"status": True, "message": "Host removido"}
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro ao remover host: {e}"}
    finally:
        fechar_conexao(conn, cursor)


# Aliases legados
def get_host_view_dashboard():
    return get_proxy_hostnames_for_dashboard()


def insert_host_view_dashboard(host: str):
    return insert_proxy_host(host)


def list_subusers_local_map() -> dict:
    """Mapa external_subuser_id → registro local (label, limite_gb, etc.)."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT external_subuser_id, login, label, criado_por, limite_gb, ativo
            FROM painel_subusers_local
            WHERE ativo = 1
            """
        )
        rows = cursor.fetchall()
        out = {}
        for r in rows:
            key = str(r.get("external_subuser_id") or "").strip()
            if key:
                out[key] = r
        return {"status": True, "map": out}
    except Exception as e:
        return {"status": False, "message": str(e)[:300], "map": {}}
    finally:
        fechar_conexao(conn, cursor)


def insert_subuser_local(
    *,
    external_subuser_id: str,
    login: str,
    label: str | None = None,
    criado_por: str | None = None,
    limite_gb: float | None = None,
) -> dict:
    """Registro local do sub-usuário criado pelo painel admin."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO painel_subusers_local
              (external_subuser_id, login, label, criado_por, limite_gb, ativo)
            VALUES (%s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
              login = VALUES(login),
              label = VALUES(label),
              criado_por = COALESCE(VALUES(criado_por), criado_por),
              limite_gb = VALUES(limite_gb),
              updated_at = CURRENT_TIMESTAMP(3)
            """,
            (
                str(external_subuser_id),
                str(login).strip(),
                (label or "").strip() or None,
                criado_por,
                limite_gb,
            ),
        )
        conn.commit()
        return {"status": True, "message": "Registro local salvo", "id": cursor.lastrowid}
    except Exception as e:
        if conn:
            conn.rollback()
        return {"status": False, "message": f"Erro ao salvar sub-usuário local: {e}"}
    finally:
        fechar_conexao(conn, cursor)