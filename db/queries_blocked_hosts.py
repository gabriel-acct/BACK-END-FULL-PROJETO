"""Hosts/domínios bloqueados globalmente (painel admin)."""

from db._db_helpers import fechar_conexao
from db.conexao import conexao


def _normalize_blocked_hostname(hostname: str) -> str:
    host = (hostname or "").strip().lower()
    if not host:
        raise ValueError("Domínio inválido")
    if host.startswith("http://"):
        host = host[7:]
    elif host.startswith("https://"):
        host = host[8:]
    host = host.split("/")[0].split(":")[0].strip()
    if host.startswith("www."):
        host = host[4:]
    if not host or len(host) > 253 or " " in host:
        raise ValueError("Domínio inválido")
    return host


def list_blocked_hosts(*, only_active: bool = False) -> dict:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        sql = """
            SELECT id, hostname, sort_order, ativo, protegido_painel, criado_em, atualizado_em
            FROM painel_blocked_hosts
        """
        if only_active:
            sql += " WHERE ativo = 1"
        sql += " ORDER BY sort_order ASC, hostname ASC"
        cursor.execute(sql)
        rows = cursor.fetchall()
        return {"status": True, "message": "Hosts bloqueados carregados", "hosts": rows}
    except Exception as e:
        err = str(e)
        if "1146" in err or "doesn't exist" in err.lower():
            return {
                "status": True,
                "message": "Tabela de hosts bloqueados não aplicada",
                "hosts": [],
            }
        return {"status": False, "message": f"Erro ao listar hosts bloqueados: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def get_active_blocked_hostnames() -> dict:
    listed = list_blocked_hosts(only_active=True)
    if not listed["status"]:
        return listed
    hostnames = [r["hostname"] for r in listed.get("hosts") or []]
    return {
        "status": True,
        "message": "Hosts bloqueados ativos",
        "hosts": hostnames,
    }


def get_all_panel_blocked_hostnames() -> dict:
    """Todos os domínios já cadastrados no painel (ativos ou inativos)."""
    listed = list_blocked_hosts(only_active=False)
    if not listed["status"]:
        return listed
    hostnames = [r["hostname"] for r in listed.get("hosts") or []]
    return {
        "status": True,
        "message": "Hosts do painel (cadastro)",
        "hosts": hostnames,
    }


def get_blocked_host_row(host_id: int) -> dict:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, hostname, sort_order, ativo, protegido_painel
            FROM painel_blocked_hosts
            WHERE id = %s
            LIMIT 1
            """,
            (int(host_id),),
        )
        row = cursor.fetchone()
        if not row:
            return {"status": False, "message": "Host bloqueado não encontrado"}
        return {"status": True, "host": row}
    except Exception as e:
        return {"status": False, "message": f"Erro ao buscar host: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def insert_blocked_host(hostname: str, sort_order: int = 0) -> dict:
    try:
        host = _normalize_blocked_hostname(hostname)
    except ValueError as e:
        return {"status": False, "message": str(e)}

    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO painel_blocked_hosts (hostname, sort_order, ativo, protegido_painel)
            VALUES (%s, %s, 1, 1)
            """,
            (host, int(sort_order)),
        )
        conn.commit()
        return {
            "status": True,
            "message": "Host bloqueado cadastrado",
            "id": cursor.lastrowid,
            "hostname": host,
        }
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        err = str(e)
        if "1062" in err or "Duplicate" in err:
            return {"status": False, "message": f"Domínio já cadastrado: {host}"}
        return {"status": False, "message": f"Erro ao cadastrar host bloqueado: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def update_blocked_host(
    host_id: int,
    *,
    hostname: str | None = None,
    sort_order: int | None = None,
    ativo: int | bool | None = None,
) -> dict:
    fields: list[str] = []
    params: list = []

    if hostname is not None:
        try:
            host = _normalize_blocked_hostname(hostname)
        except ValueError as e:
            return {"status": False, "message": str(e)}
        fields.append("hostname = %s")
        params.append(host)

    if sort_order is not None:
        fields.append("sort_order = %s")
        params.append(int(sort_order))

    if ativo is not None:
        fields.append("ativo = %s")
        params.append(1 if ativo in (1, True, "1", "true") else 0)

    if not fields:
        return {"status": False, "message": "Nenhum campo para atualizar"}

    params.append(int(host_id))
    conn = None
    cursor = None
    try:
        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE painel_blocked_hosts SET {', '.join(fields)} WHERE id = %s",
            tuple(params),
        )
        if cursor.rowcount == 0:
            return {"status": False, "message": "Host bloqueado não encontrado"}
        conn.commit()
        return {"status": True, "message": "Host bloqueado atualizado"}
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return {"status": False, "message": f"Erro ao atualizar: {e}"}
    finally:
        fechar_conexao(conn, cursor)


def delete_blocked_host(host_id: int) -> dict:
    conn = None
    cursor = None
    try:
        found = get_blocked_host_row(host_id)
        if not found.get("status"):
            return found
        hostname = found["host"]["hostname"]

        conn = conexao()
        if conn is None:
            return {"status": False, "message": "Erro ao conectar no banco de dados"}

        cursor = conn.cursor()
        cursor.execute("DELETE FROM painel_blocked_hosts WHERE id = %s", (int(host_id),))
        if cursor.rowcount == 0:
            return {"status": False, "message": "Host bloqueado não encontrado"}
        conn.commit()
        return {
            "status": True,
            "message": "Host bloqueado removido",
            "hostname": hostname,
        }
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return {"status": False, "message": f"Erro ao remover: {e}"}
    finally:
        fechar_conexao(conn, cursor)
