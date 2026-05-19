"""Notificações do painel (admin → sub-usuários)."""

from __future__ import annotations

import logging

from db._db_helpers import fechar_conexao
from db.conexao import conexao

_log = logging.getLogger(__name__)


def _subuser_visible_sql(alias_n: str = "n") -> str:
    return f"""
      ({alias_n}.alvo_tipo = 'todos'
       OR EXISTS (
         SELECT 1 FROM painel_notificacoes_alvos a
         WHERE a.notificacao_id = {alias_n}.id AND a.subuser_id = %s
       ))
    """


def _not_oculto_sql() -> str:
    return "(e.oculto IS NULL OR e.oculto = 0)"


def list_notificacoes_admin(limit: int = 50, offset: int = 0) -> list:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT n.id, n.titulo, n.mensagem, n.tipo, n.alvo_tipo, n.ativo,
                   n.criado_por, n.criado_em, n.atualizado_em, n.expira_em,
                   (SELECT COUNT(*) FROM painel_notificacoes_alvos a WHERE a.notificacao_id = n.id) AS alvos_count
            FROM painel_notificacoes n
            ORDER BY n.id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        fechar_conexao(conn, cursor)


def count_notificacoes_admin() -> int:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return 0
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS c FROM painel_notificacoes")
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        fechar_conexao(conn, cursor)


def get_notificacao_admin(nid: int) -> dict | None:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return None
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, titulo, mensagem, tipo, alvo_tipo, ativo, criado_por, criado_em, expira_em
            FROM painel_notificacoes WHERE id = %s LIMIT 1
            """,
            (int(nid),),
        )
        row = cursor.fetchone()
        if not row:
            return None
        cursor.execute(
            "SELECT subuser_id FROM painel_notificacoes_alvos WHERE notificacao_id = %s",
            (int(nid),),
        )
        row["alvos"] = [str(r["subuser_id"]) for r in cursor.fetchall()]
        return row
    except Exception:
        return None
    finally:
        fechar_conexao(conn, cursor)


def normalize_subuser_ids_for_alvos(raw_ids: list[str] | None) -> list[str]:
    """
    Normaliza IDs para painel_notificacoes_alvos.
    Aceita ID numérico (JWT sub) ou login do sub-usuário.
    """
    if not raw_ids:
        return []
    out: list[str] = []
    login_to_id: dict[str, str] | None = None

    for item in raw_ids:
        s = str(item).strip()
        if not s:
            continue
        if s.isdigit():
            out.append(s)
            continue
        if login_to_id is None:
            login_to_id = {}
            try:
                from app.service.sub_usuarios import get_all_user

                data = get_all_user()
                if data.get("status"):
                    for u in data.get("users") or []:
                        login = str(u.get("login") or "").strip().lower()
                        uid = u.get("id")
                        if login and uid is not None:
                            login_to_id[login] = str(uid)
            except Exception as e:
                _log.warning("normalize_subuser_ids_for_alvos: %s", e)
        mapped = (login_to_id or {}).get(s.lower())
        out.append(mapped if mapped else s)

    seen: set[str] = set()
    unique: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            unique.append(x[:64])
    return unique


def create_notificacao(
    *,
    titulo: str,
    mensagem: str,
    tipo: str,
    alvo_tipo: str,
    criado_por: str,
    subuser_ids: list[str] | None = None,
    expira_em: str | None = None,
) -> tuple[int | None, str | None]:
    tipo = (tipo or "normal").strip().lower()
    if tipo not in ("normal", "critico"):
        tipo = "normal"
    alvo = (alvo_tipo or "todos").strip().lower()
    if alvo not in ("todos", "usuarios"):
        alvo = "todos"
    if alvo == "usuarios" and not subuser_ids:
        return None, "Informe ao menos um ID de sub-usuário para alvo específico"

    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return None, "Sem conexão com o banco"
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO painel_notificacoes
              (titulo, mensagem, tipo, alvo_tipo, ativo, criado_por, expira_em)
            VALUES (%s, %s, %s, %s, 1, %s, %s)
            """,
            (
                titulo[:200],
                mensagem,
                tipo,
                alvo,
                criado_por[:64],
                expira_em,
            ),
        )
        nid = int(cursor.lastrowid)
        if alvo == "usuarios" and subuser_ids:
            for sid in normalize_subuser_ids_for_alvos(subuser_ids):
                cursor.execute(
                    """
                    INSERT IGNORE INTO painel_notificacoes_alvos (notificacao_id, subuser_id)
                    VALUES (%s, %s)
                    """,
                    (nid, sid),
                )
        conn.commit()
        return nid, None
    except Exception as e:
        if conn:
            conn.rollback()
        return None, str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def update_notificacao_ativo(nid: int, ativo: bool) -> bool:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE painel_notificacoes SET ativo = %s WHERE id = %s",
            (1 if ativo else 0, int(nid)),
        )
        conn.commit()
        return cursor.rowcount >= 1
    except Exception:
        if conn:
            conn.rollback()
        return False
    finally:
        fechar_conexao(conn, cursor)


def list_notificacoes_for_subuser(subuser_id: str, limit: int = 50) -> list:
    subuser_id = str(subuser_id).strip()[:64]
    if not subuser_id:
        return []
    limit = max(1, min(int(limit), 100))
    vis = _subuser_visible_sql("n")
    oculto = _not_oculto_sql()
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT n.id, n.titulo, n.mensagem, n.tipo, n.criado_em,
                   COALESCE(e.lida, 0) AS lida,
                   COALESCE(e.critico_ack, 0) AS critico_ack
            FROM painel_notificacoes n
            LEFT JOIN painel_notificacoes_estado e
              ON e.notificacao_id = n.id AND e.subuser_id = %s
            WHERE n.ativo = 1
              AND (n.expira_em IS NULL OR n.expira_em > NOW())
              AND {oculto}
              AND {vis}
            ORDER BY n.criado_em DESC
            LIMIT %s
            """,
            (subuser_id, subuser_id, limit),
        )
        return cursor.fetchall()
    except Exception as e:
        _log.warning("list_notificacoes_for_subuser(%s): %s", subuser_id, e)
        return []
    finally:
        fechar_conexao(conn, cursor)


def count_unread_for_subuser(subuser_id: str) -> int:
    subuser_id = str(subuser_id).strip()[:64]
    vis = _subuser_visible_sql("n")
    oculto = _not_oculto_sql()
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return 0
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT COUNT(*) AS c
            FROM painel_notificacoes n
            LEFT JOIN painel_notificacoes_estado e
              ON e.notificacao_id = n.id AND e.subuser_id = %s
            WHERE n.ativo = 1
              AND n.tipo = 'normal'
              AND (n.expira_em IS NULL OR n.expira_em > NOW())
              AND (e.lida IS NULL OR e.lida = 0)
              AND {oculto}
              AND {vis}
            """,
            (subuser_id, subuser_id),
        )
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception as e:
        _log.warning("count_unread_for_subuser(%s): %s", subuser_id, e)
        return 0
    finally:
        fechar_conexao(conn, cursor)


def list_critical_pending_for_subuser(subuser_id: str) -> list:
    """Avisos críticos ainda não confirmados no painel."""
    subuser_id = str(subuser_id).strip()[:64]
    vis = _subuser_visible_sql("n")
    oculto = _not_oculto_sql()
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT n.id, n.titulo, n.mensagem, n.tipo, n.criado_em
            FROM painel_notificacoes n
            LEFT JOIN painel_notificacoes_estado e
              ON e.notificacao_id = n.id AND e.subuser_id = %s
            WHERE n.ativo = 1
              AND n.tipo = 'critico'
              AND (n.expira_em IS NULL OR n.expira_em > NOW())
              AND (e.critico_ack IS NULL OR e.critico_ack = 0)
              AND {oculto}
              AND {vis}
            ORDER BY n.criado_em ASC
            LIMIT 10
            """,
            (subuser_id, subuser_id),
        )
        return cursor.fetchall()
    except Exception as e:
        _log.warning("list_critical_pending_for_subuser(%s): %s", subuser_id, e)
        return []
    finally:
        fechar_conexao(conn, cursor)


def mark_notificacao_lida(notificacao_id: int, subuser_id: str) -> bool:
    return _upsert_estado_simple(notificacao_id, subuser_id, lida=1)


def mark_critico_ack(notificacao_id: int, subuser_id: str) -> bool:
    return _upsert_estado_simple(notificacao_id, subuser_id, lida=1, critico_ack=1)


def hide_notificacao_for_subuser(notificacao_id: int, subuser_id: str) -> bool:
    """Remove da lista só deste usuário (não apaga para os demais)."""
    return _upsert_estado_simple(
        notificacao_id,
        subuser_id,
        lida=1,
        critico_ack=1,
        oculto=1,
    )


def delete_notificacao_admin(nid: int) -> bool:
    """Exclui a notificação para todos os usuários."""
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False
        cursor = conn.cursor()
        cursor.execute("DELETE FROM painel_notificacoes WHERE id = %s", (int(nid),))
        conn.commit()
        return cursor.rowcount >= 1
    except Exception as e:
        if conn:
            conn.rollback()
        _log.warning("delete_notificacao_admin(%s): %s", nid, e)
        return False
    finally:
        fechar_conexao(conn, cursor)


def _upsert_estado_simple(
    notificacao_id: int,
    subuser_id: str,
    *,
    lida: int = 0,
    critico_ack: int = 0,
    oculto: int = 0,
) -> bool:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO painel_notificacoes_estado
              (notificacao_id, subuser_id, lida, critico_ack, oculto)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              lida = GREATEST(lida, VALUES(lida)),
              critico_ack = GREATEST(critico_ack, VALUES(critico_ack)),
              oculto = GREATEST(oculto, VALUES(oculto)),
              atualizado_em = CURRENT_TIMESTAMP(3)
            """,
            (
                int(notificacao_id),
                str(subuser_id).strip()[:64],
                int(lida),
                int(critico_ack),
                int(oculto),
            ),
        )
        conn.commit()
        return True
    except Exception:
        if conn:
            conn.rollback()
        return False
    finally:
        fechar_conexao(conn, cursor)


def subuser_can_see_notificacao(notificacao_id: int, subuser_id: str) -> bool:
    subuser_id = str(subuser_id).strip()[:64]
    vis = _subuser_visible_sql("n")
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            f"""
            SELECT n.id FROM painel_notificacoes n
            WHERE n.id = %s AND n.ativo = 1
              AND (n.expira_em IS NULL OR n.expira_em > NOW())
              AND {vis}
            LIMIT 1
            """,
            (int(notificacao_id), subuser_id),
        )
        return cursor.fetchone() is not None
    except Exception as e:
        _log.warning("subuser_can_see_notificacao(%s, %s): %s", notificacao_id, subuser_id, e)
        return False
    finally:
        fechar_conexao(conn, cursor)
