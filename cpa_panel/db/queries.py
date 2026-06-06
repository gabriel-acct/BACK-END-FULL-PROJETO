"""Queries usadas apenas pelo painel web (leitura de usuário, logs, troca de porta)."""
from __future__ import annotations

import json
import logging
import secrets
import string
import mysql.connector

from cpa_panel.db.connection import conexao_bd

_logger_payment = logging.getLogger(__name__)


def _normalize_user_row(row: dict | None) -> dict | None:
    """Chaves sempre em minúsculas — evita dict do MySQL/cursor com casing diferente.

    mysql-connector-python 9+ pode devolver linhas tipo Row/Mapping que não são dict;
    também evita nomes de coluna como bytes.
    """
    if row is None:
        return None
    src: dict
    try:
        if isinstance(row, dict):
            src = row
        else:
            src = dict(row)
    except Exception:
        try:
            src = {k: row[k] for k in row}  # type: ignore[arg-type,index]
        except Exception:
            _logger_payment.exception("queries: falha ao materializar linha do MySQL tipo=%s", type(row).__name__)
            return None

    out: dict = {}
    for k, v in src.items():
        if isinstance(k, bytes):
            kk = k.decode("utf-8", "replace").lower()
        else:
            kk = str(k).lower()
        out[kk] = v
    return out


def _criado_por_str(row: dict | None) -> str:
    """Lê criado_por com tolerância a chave divergente no dict ou tipo bytes."""
    if not row:
        return ""
    v = row.get("criado_por")
    if v is None:
        for key, val in row.items():
            if str(key).lower() == "criado_por":
                v = val
                break
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        try:
            v = v.decode("utf-8", "replace")
        except Exception:
            return ""
    return str(v).strip()


def get_users(username):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT *
        FROM usuarios_proxy
        WHERE username = %s
        LIMIT 1
        """,
        (username,),
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    try:
        return _normalize_user_row(user)
    except Exception:
        _logger_payment.exception("queries.get_users: normalização da linha falhou para username=%s", username)
        return user if isinstance(user, dict) else None


def get_user_for_auth(username):
    """Usuário com JOIN em cargo (RBAC). Se as tabelas ainda não existirem, cai em get_users."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.*, c.slug AS cargo_slug, c.nome AS cargo_nome,
                   c.bypass_all AS cargo_bypass_all,
                   p.nome AS pais_nome,
                   COALESCE(t.threads, 1800) AS threads
            FROM usuarios_proxy u
            LEFT JOIN painel_cargos c ON u.cargo_id = c.id
            LEFT JOIN painel_paises p ON u.pais_id = p.id
            LEFT JOIN painel_usuario_threads t ON t.username = u.username
            WHERE u.username = %s
            LIMIT 1
            """,
            (username,),
        )
        row = cursor.fetchone()
        try:
            return _normalize_user_row(row)
        except Exception:
            _logger_payment.exception(
                "queries.get_user_for_auth: normalização falhou para username=%s", username,
            )
            return row if isinstance(row, dict) else get_users(username)
    except Exception:
        return get_users(username)
    finally:
        cursor.close()
        conn.close()


def list_permissions_for_cargo(cargo_id: int) -> list[str]:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT permission_code AS code
            FROM painel_cargo_permissoes
            WHERE cargo_id = %s
            """,
            (cargo_id,),
        )
        rows = cursor.fetchall()
        return [r["code"] for r in rows]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_all_permission_definitions():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT code, descricao AS description
            FROM painel_permissions
            ORDER BY code
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


ME_LOGS_CAP = 200
ME_LOGS_PAGE_SIZE = 50


def count_proxy_logs_capped(
    username: str,
    max_cap: int = ME_LOGS_CAP,
    created_after=None,
    created_before_exclusive=None,
) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = ["username = %s"]
        params: list = [username]
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        cursor.execute(f"SELECT COUNT(*) AS c FROM proxy_access_logs {where_sql}", tuple(params))
        row = cursor.fetchone()
        c = int(row["c"]) if row else 0
        return min(max_cap, c)
    except Exception:
        return 0
    finally:
        cursor.close()
        conn.close()


def list_proxy_logs_paginated(
    username: str,
    page: int = 0,
    page_size: int = ME_LOGS_PAGE_SIZE,
    max_total: int = ME_LOGS_CAP,
    created_after=None,
    created_before_exclusive=None,
):
    """No máximo `max_total` registros mais recentes; fatia `page_size` por página."""
    page = max(0, int(page))
    page_size = max(1, min(int(page_size), ME_LOGS_PAGE_SIZE))
    max_total = max(1, min(int(max_total), ME_LOGS_CAP))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = ["username = %s"]
        params: list = [username]
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        cursor.execute(
            f"SELECT COUNT(*) AS c FROM proxy_access_logs {where_sql}",
            tuple(params),
        )
        row = cursor.fetchone()
        raw_total = int(row["c"]) if row else 0
        total_available = min(max_total, raw_total)
        offset = page * page_size
        if offset >= total_available:
            return []
        limit = min(page_size, total_available - offset)
        cursor.execute(
            f"""
            SELECT id, username, porta, dest_host, dest_display, method,
                   bytes_upload, bytes_download, upstream_proxy, created_at
            FROM proxy_access_logs
            {where_sql}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params) + (limit, offset),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def list_proxy_logs(username, limit=100):
    limit = max(1, min(int(limit), 500))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, username, porta, dest_host, dest_display, method,
               bytes_upload, bytes_download, upstream_proxy, created_at
        FROM proxy_access_logs
        WHERE username = %s
        ORDER BY id DESC
        LIMIT %s
        """,
        (username, limit),
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def update_user_port_exclusive(username, current_porta, new_porta):
    """Altera porta apenas se new_porta não estiver em uso por outro usuário."""
    from cpa_panel.gateway_ports import is_allowed_port

    current_porta = int(current_porta)
    new_porta = int(new_porta)
    if new_porta != current_porta and not is_allowed_port(new_porta):
        return False, "Porta deve ser 823 (HTTP) ou 824 (SOCKS5)"
    if new_porta == current_porta:
        return True, None

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        # cursor.execute(
        #     """
        #     SELECT username FROM usuarios_proxy
        #     WHERE porta = %s AND username <> %s
        #     LIMIT 1
        #     """,
        #     (new_porta, username),
        # )
        # row = cursor.fetchone()
        # if row:
        #     return False, "Esta porta já está em uso por outro usuário"

        cursor.execute(
            """
            UPDATE usuarios_proxy
            SET porta = %s
            WHERE username = %s AND porta = %s
            """,
            (new_porta, username, current_porta),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return False, "Não foi possível atualizar (porta atual incorreta ou usuário inexistente)"

        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def list_paises_para_painel():
    """Países ativos para seleção no painel (lista em painel_paises)."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, nome, codigo_iso2
            FROM painel_paises
            WHERE ativo = 1
            ORDER BY ordem ASC, nome ASC
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def pais_exists_ativo(pais_id: int) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM painel_paises WHERE id = %s AND ativo = 1 LIMIT 1",
            (int(pais_id),),
        )
        return cursor.fetchone() is not None
    except Exception:
        return False
    finally:
        cursor.close()
        conn.close()


def get_pais_id_brasil() -> int | None:
    """Id do país Brasil (ISO BR) em painel_paises; None se tabela/linha inexistente."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM painel_paises WHERE codigo_iso2 = 'BR' AND ativo = 1 LIMIT 1",
        )
        row = cursor.fetchone()
        return int(row["id"]) if row else None
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def update_usuario_pais(username: str, pais_id: int | None) -> tuple[bool, str | None]:
    """Define pais_id do usuário (NULL para limpar). Valida existe em painel_paises."""
    if pais_id is not None:
        if not pais_exists_ativo(pais_id):
            return False, "País inválido ou indisponível"

    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            UPDATE usuarios_proxy SET pais_id = %s WHERE username = %s
            """,
            (pais_id, username),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return False, "Usuário não encontrado"
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def insert_audit_log(actor_username: str, action: str, target_type: str | None, target_key: str | None, detail: str | None):
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_audit_log (actor_username, action, target_type, target_key, detail)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (actor_username, action, target_type, target_key, detail),
        )
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def list_audit_logs(
    limit: int = 100,
    offset: int = 0,
    created_after=None,
    created_before_exclusive=None,
):
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = []
        params: list = []
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        params.extend([limit, offset])
        cursor.execute(
            f"""
            SELECT id, actor_username, action, target_type, target_key, detail, created_at
            FROM painel_audit_log
            {where_sql}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def count_audit_logs(created_after=None, created_before_exclusive=None) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = []
        params: list = []
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        cursor.execute(f"SELECT COUNT(*) AS c FROM painel_audit_log {where_sql}", tuple(params))
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    finally:
        cursor.close()
        conn.close()


def list_audit_logs_for_actor(
    actor_username: str,
    limit: int = 100,
    offset: int = 0,
    created_after=None,
    created_before_exclusive=None,
):
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = ["actor_username = %s"]
        params: list = [str(actor_username).strip()]
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        params.extend([limit, offset])
        cursor.execute(
            f"""
            SELECT id, actor_username, action, target_type, target_key, detail, created_at
            FROM painel_audit_log
            {where_sql}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def count_audit_logs_for_actor(
    actor_username: str,
    created_after=None,
    created_before_exclusive=None,
) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = ["actor_username = %s"]
        params: list = [str(actor_username).strip()]
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        cursor.execute(f"SELECT COUNT(*) AS c FROM painel_audit_log {where_sql}", tuple(params))
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    finally:
        cursor.close()
        conn.close()


def audit_ranking_user_creates(
    created_after=None,
    created_before_exclusive=None,
    limit: int = 80,
):
    """Ranking: quem criou mais usuários proxy (painel_audit_log.action = user.create)."""
    limit = max(1, min(int(limit), 300))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    wheres = ["action = %s"]
    params: list = ["user.create"]
    if created_after is not None:
        wheres.append("created_at >= %s")
        params.append(created_after)
    if created_before_exclusive is not None:
        wheres.append("created_at < %s")
        params.append(created_before_exclusive)
    where_sql = "WHERE " + " AND ".join(wheres)
    try:
        cursor.execute(
            f"""
            SELECT actor_username AS ator, COUNT(*) AS quantidade
            FROM painel_audit_log
            {where_sql}
            GROUP BY actor_username
            ORDER BY quantidade DESC, ator ASC
            LIMIT %s
            """,
            tuple(params) + (limit,),
        )
        rows = cursor.fetchall()
        return [{"ator": str(r["ator"]), "quantidade": int(r["quantidade"])} for r in (rows or [])]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_audit_user_create_events(created_after=None, created_before_exclusive=None, limit: int = 200):
    """Registros auditados de criação de usuário (ordem mais recentes primeiro)."""
    limit = max(1, min(int(limit), 800))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    wheres = ["action = %s"]
    params: list = ["user.create"]
    if created_after is not None:
        wheres.append("created_at >= %s")
        params.append(created_after)
    if created_before_exclusive is not None:
        wheres.append("created_at < %s")
        params.append(created_before_exclusive)
    where_sql = "WHERE " + " AND ".join(wheres)
    try:
        cursor.execute(
            f"""
            SELECT id, actor_username, target_key, detail, created_at
            FROM painel_audit_log
            {where_sql}
            ORDER BY id DESC
            LIMIT %s
            """,
            tuple(params) + (limit,),
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_users_admin(created_after=None, created_before_exclusive=None):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    date_params: list = []
    if created_after is not None:
        date_params.append(created_after)
    if created_before_exclusive is not None:
        date_params.append(created_before_exclusive)

    sql_legacy = """
            SELECT u.username, u.senha, u.porta, u.status, u.limite_gb, u.usado_bytes,
                   u.custo_pago, u.ceo_limite_gb_basico,
                   u.cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome,
                   c.bypass_all AS cargo_bypass_all,
                   u.criado_por
            FROM usuarios_proxy u
            LEFT JOIN painel_cargos c ON u.cargo_id = c.id
            ORDER BY u.username
            """
    try:
        for col in ("criado_em", "created_at"):
            date_parts = []
            if created_after is not None:
                date_parts.append(f"u.{col} >= %s")
            if created_before_exclusive is not None:
                date_parts.append(f"u.{col} < %s")
            date_where = ("WHERE " + " AND ".join(date_parts)) if date_parts else ""
            sql_full = f"""
            SELECT u.username, u.senha, u.porta, u.status, u.limite_gb, u.usado_bytes,
                   u.custo_pago, u.ceo_limite_gb_basico,
                   u.cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome,
                   c.bypass_all AS cargo_bypass_all,
                   u.{col} AS criado_em,
                   u.criado_por
            FROM usuarios_proxy u
            LEFT JOIN painel_cargos c ON u.cargo_id = c.id
            {date_where}
            ORDER BY u.username
            """
            try:
                cursor.execute(sql_full, tuple(date_params))
                return cursor.fetchall()
            except Exception:
                continue

        try:
            cursor.execute(sql_legacy)
            rows = cursor.fetchall()
        except Exception:
            cursor.execute(
                """
                SELECT u.username, u.senha, u.porta, u.status, u.limite_gb, u.usado_bytes,
                       u.custo_pago, u.ceo_limite_gb_basico,
                       u.cargo_id, c.slug AS cargo_slug, c.nome AS cargo_nome,
                       c.bypass_all AS cargo_bypass_all
                FROM usuarios_proxy u
                LEFT JOIN painel_cargos c ON u.cargo_id = c.id
                ORDER BY u.username
                """
            )
            rows = cursor.fetchall()
        for r in rows:
            r.setdefault("criado_em", None)
            r.setdefault("criado_por", None)
            r.setdefault("custo_pago", 0)
            r.setdefault("ceo_limite_gb_basico", None)
        return rows
    finally:
        cursor.close()
        conn.close()


def update_user_custo_pago(username: str, custo_pago: int) -> bool:
    """Define custo_pago (0 ou 1). Se 1, grava ceo_limite_gb_basico = limite_gb atual. Se 0, limpa baseline."""
    un = (username or "").strip()
    if not un:
        return False
    v = 1 if int(custo_pago) else 0
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        if v == 1:
            cursor.execute(
                "UPDATE usuarios_proxy SET custo_pago = 1, ceo_limite_gb_basico = limite_gb WHERE username = %s",
                (un,),
            )
        else:
            cursor.execute(
                "UPDATE usuarios_proxy SET custo_pago = 0, ceo_limite_gb_basico = NULL WHERE username = %s",
                (un,),
            )
        ok = cursor.rowcount >= 1
        conn.commit()
        return ok
    except Exception:
        conn.rollback()
        try:
            cursor.execute(
                "UPDATE usuarios_proxy SET custo_pago = %s WHERE username = %s",
                (v, un),
            )
            ok = cursor.rowcount >= 1
            conn.commit()
            return ok
        except Exception:
            conn.rollback()
            return False
    finally:
        cursor.close()
        conn.close()


def mark_custo_pago_all_usado_bytes_positive() -> tuple[int | None, str | None]:
    """Marca custo_pago = 1 em todas as contas com usado_bytes > 0; baseline = limite_gb atual."""
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_proxy SET custo_pago = 1, ceo_limite_gb_basico = limite_gb WHERE usado_bytes > 0"
        )
        n = int(cursor.rowcount or 0)
        conn.commit()
        return (n, None)
    except Exception as e:
        conn.rollback()
        try:
            cursor.execute("UPDATE usuarios_proxy SET custo_pago = 1 WHERE usado_bytes > 0")
            n = int(cursor.rowcount or 0)
            conn.commit()
            return (n, None)
        except Exception as e2:
            return (None, str(e2))
    finally:
        cursor.close()
        conn.close()


def clear_all_custo_pago() -> tuple[int | None, str | None]:
    """Zera custo_pago e baseline ARE CEO nas contas onde estava marcado."""
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_proxy SET custo_pago = 0, ceo_limite_gb_basico = NULL WHERE custo_pago <> 0"
        )
        n = int(cursor.rowcount or 0)
        conn.commit()
        return (n, None)
    except Exception as e:
        conn.rollback()
        try:
            cursor.execute("UPDATE usuarios_proxy SET custo_pago = 0 WHERE custo_pago <> 0")
            n = int(cursor.rowcount or 0)
            conn.commit()
            return (n, None)
        except Exception as e2:
            return (None, str(e2))
    finally:
        cursor.close()
        conn.close()


def get_ceo_valor_extra_reais() -> float:
    """Soma opcional ao total em R$ da ARE CEO. Tabela opcional ``painel_ceo_settings``."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT valor_extra_reais
            FROM painel_ceo_settings
            WHERE id = 1
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if not row:
            return 0.0
        return float(row.get("valor_extra_reais") or 0)
    except Exception:
        return 0.0
    finally:
        cursor.close()
        conn.close()


def set_ceo_valor_extra_reais(valor: float) -> tuple[bool, str | None]:
    """Upsert linha id=1 em painel_ceo_settings."""
    v = float(valor)
    if v < 0 or v > 1_000_000_000:
        return False, "valor_extra_reais fora do intervalo permitido"
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_ceo_settings (id, valor_extra_reais)
            VALUES (1, %s)
            ON DUPLICATE KEY UPDATE valor_extra_reais = VALUES(valor_extra_reais)
            """,
            (v,),
        )
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def count_usuarios_proxy_rows() -> int:
    """Total de linhas na tabela usuarios_proxy."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) AS c FROM usuarios_proxy")
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        cursor.close()
        conn.close()


def count_usuarios_proxy_sem_criado_em() -> int | None:
    """Contas com data de criação NULL; tenta coluna criado_em e, se falhar, created_at. None = coluna inexistente."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        for col in ("criado_em", "created_at"):
            try:
                cursor.execute(f"SELECT COUNT(*) AS c FROM usuarios_proxy WHERE {col} IS NULL")
                row = cursor.fetchone()
                return int(row["c"]) if row else None
            except Exception:
                continue
        return None
    finally:
        cursor.close()
        conn.close()


def count_usuarios_proxy_null_created_at() -> int | None:
    """Alias semântico — use count_usuarios_proxy_sem_criado_em."""
    return count_usuarios_proxy_sem_criado_em()


def count_usuarios_proxy_by_created_bounds(created_after=None, created_before_exclusive=None) -> int | None:
    """Contagem por intervalo em criado_em (ou created_at em instalações legadas)."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    for col in ("criado_em", "created_at"):
        wheres: list[str] = []
        params: list = []
        if created_after is not None:
            wheres.append(f"{col} >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append(f"{col} < %s")
            params.append(created_before_exclusive)
        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        try:
            cursor.execute(f"SELECT COUNT(*) AS c FROM usuarios_proxy {where_sql}", tuple(params))
            row = cursor.fetchone()
            return int(row["c"]) if row else 0
        except Exception:
            continue
    return None


def aggregate_usuarios_proxy_gb(created_after=None, created_before_exclusive=None) -> dict | None:
    """
    Soma limite_gb (capacidade contratada) e usado_bytes (tráfego) nas linhas de usuarios_proxy.
    Sem filtro de datas: todas as contas. Com datas: mesma semântica de criação que count_usuarios_proxy_by_created_bounds.
    Retorna None se não existir coluna de data quando o filtro estiver ativo.
    """
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        has_date_filter = created_after is not None or created_before_exclusive is not None
        if not has_date_filter:
            cursor.execute(
                """
                SELECT COUNT(*) AS contas,
                       COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS soma_limite_gb,
                       COALESCE(SUM(COALESCE(usado_bytes, 0)), 0) AS soma_usado_bytes
                FROM usuarios_proxy
                """
            )
            row = cursor.fetchone()
            if not row:
                return {"contas": 0, "soma_limite_gb": 0.0, "soma_usado_bytes": 0}
            return {
                "contas": int(row.get("contas") or 0),
                "soma_limite_gb": float(row.get("soma_limite_gb") or 0),
                "soma_usado_bytes": int(row.get("soma_usado_bytes") or 0),
            }

        for col in ("criado_em", "created_at"):
            wheres: list[str] = []
            params: list = []
            if created_after is not None:
                wheres.append(f"{col} >= %s")
                params.append(created_after)
            if created_before_exclusive is not None:
                wheres.append(f"{col} < %s")
                params.append(created_before_exclusive)
            where_sql = "WHERE " + " AND ".join(wheres)
            try:
                cursor.execute(
                    f"""
                    SELECT COUNT(*) AS contas,
                           COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS soma_limite_gb,
                           COALESCE(SUM(COALESCE(usado_bytes, 0)), 0) AS soma_usado_bytes
                    FROM usuarios_proxy
                    {where_sql}
                    """,
                    tuple(params),
                )
                row = cursor.fetchone()
                if not row:
                    return {"contas": 0, "soma_limite_gb": 0.0, "soma_usado_bytes": 0}
                return {
                    "contas": int(row.get("contas") or 0),
                    "soma_limite_gb": float(row.get("soma_limite_gb") or 0),
                    "soma_usado_bytes": int(row.get("soma_usado_bytes") or 0),
                }
            except Exception:
                continue
        return None
    finally:
        cursor.close()
        conn.close()


def list_usuarios_proxy_gb_linhas(created_after=None, created_before_exclusive=None) -> list[dict] | None:
    """username + limite_gb + usado_bytes por linha; filtro de criação opcional (mesma lógica que aggregate)."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        has_date_filter = created_after is not None or created_before_exclusive is not None
        if not has_date_filter:
            try:
                cursor.execute(
                    """
                    SELECT username,
                           CAST(limite_gb AS DECIMAL(24, 8)) AS limite_gb,
                           COALESCE(usado_bytes, 0) AS usado_bytes
                    FROM usuarios_proxy
                    ORDER BY username ASC
                    """
                )
                rows = cursor.fetchall() or []
                out = []
                for r in rows:
                    out.append(
                        {
                            "username": str(r.get("username") or ""),
                            "limite_gb": float(r.get("limite_gb") or 0),
                            "usado_bytes": int(r.get("usado_bytes") or 0),
                        }
                    )
                return out
            except Exception:
                return []

        for col in ("criado_em", "created_at"):
            wheres: list[str] = []
            params: list = []
            if created_after is not None:
                wheres.append(f"{col} >= %s")
                params.append(created_after)
            if created_before_exclusive is not None:
                wheres.append(f"{col} < %s")
                params.append(created_before_exclusive)
            where_sql = "WHERE " + " AND ".join(wheres)
            try:
                cursor.execute(
                    f"""
                    SELECT username,
                           CAST(limite_gb AS DECIMAL(24, 8)) AS limite_gb,
                           COALESCE(usado_bytes, 0) AS usado_bytes
                    FROM usuarios_proxy
                    {where_sql}
                    ORDER BY username ASC
                    """,
                    tuple(params),
                )
                rows = cursor.fetchall() or []
                out = []
                for r in rows:
                    out.append(
                        {
                            "username": str(r.get("username") or ""),
                            "limite_gb": float(r.get("limite_gb") or 0),
                            "usado_bytes": int(r.get("usado_bytes") or 0),
                        }
                    )
                return out
            except Exception:
                continue
        return None
    finally:
        cursor.close()
        conn.close()


def list_usuario_creation_counts_by_day(created_after=None, created_before_exclusive=None):
    """Agrupa contas criadas por dia (criado_em ou created_at)."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    for col in ("criado_em", "created_at"):
        wheres: list[str] = [f"{col} IS NOT NULL"]
        params: list = []
        if created_after is not None:
            wheres.append(f"{col} >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append(f"{col} < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        try:
            cursor.execute(
                f"""
                SELECT DATE({col}) AS day_ref, COUNT(*) AS cnt
                FROM usuarios_proxy
                {where_sql}
                GROUP BY DATE({col})
                ORDER BY day_ref ASC
                """,
                tuple(params),
            )
            rows = cursor.fetchall()
            out = []
            for r in rows or []:
                dr = r.get("day_ref")
                if hasattr(dr, "isoformat"):
                    day_s = dr.isoformat()[:10]
                else:
                    day_s = str(dr)[:10] if dr is not None else ""
                out.append({"day": day_s, "count": int(r.get("cnt") or 0)})
            return out
        except Exception:
            continue
    return []


def update_user_status(username: str, status: int) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_proxy SET status = %s WHERE username = %s",
            (int(status), username),
        )
        ok = cursor.rowcount >= 1
        conn.commit()
        return ok
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def sum_limite_gb_criados_por(owner_username: str, exceto_username: str | None = None) -> float:
    """Soma limite_gb das contas com criado_por = owner (opcionalmente exclui um username)."""
    owner_username = (owner_username or "").strip()
    if not owner_username:
        return 0.0
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        if exceto_username:
            cursor.execute(
                """
                SELECT COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS s
                FROM usuarios_proxy
                WHERE criado_por = %s AND username <> %s
                """,
                (owner_username, (exceto_username or "").strip()),
            )
        else:
            cursor.execute(
                """
                SELECT COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS s
                FROM usuarios_proxy
                WHERE criado_por = %s
                """,
                (owner_username,),
            )
        row = cursor.fetchone()
        return float(row["s"]) if row else 0.0
    except Exception:
        return 0.0
    finally:
        cursor.close()
        conn.close()


def pool_disponivel_gb_socio(socio_username: str) -> float:
    """GB livres no pool do sócio: limite_gb do sócio − soma limite_gb dos filhos (criado_por)."""
    su = (socio_username or "").strip()
    if not su:
        return 0.0
    socio = get_users(su)
    if not socio:
        return 0.0
    pool = float(socio.get("limite_gb") or 0)
    alloc = sum_limite_gb_criados_por(su, None)
    return max(0.0, round(pool - alloc, 6))


def list_socio_responsavel_overview_rows() -> list[dict]:
    """
    Sócios de topo + pool + flags PushinPay/branding.
    Usado pelo dono (ARE CEO).
    """
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.username,
                   CAST(u.limite_gb AS DECIMAL(24, 8)) AS pool_limite_gb,
                   CAST(COALESCE(a.alocado_gb, 0) AS DECIMAL(24, 8)) AS alocado_gb,
                   CAST(u.limite_gb AS DECIMAL(24, 8)) - CAST(COALESCE(a.alocado_gb, 0) AS DECIMAL(24, 8)) AS disponivel_gb,
                   u.porta AS gateway_porta,
                   (sp.socio_username IS NOT NULL AND LENGTH(TRIM(sp.api_token)) > 0) AS pushinpay_socio_ativo,
                   sp.api_base AS pushinpay_api_base,
                   pb.titulo_sidebar AS brand_titulo,
                   pb.logo_url AS brand_logo_url
            FROM usuarios_proxy u
            INNER JOIN painel_cargos c ON u.cargo_id = c.id AND c.slug = 'socio'
            LEFT JOIN (
                SELECT criado_por AS owner_u,
                       COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS alocado_gb
                FROM usuarios_proxy
                WHERE criado_por IS NOT NULL AND TRIM(criado_por) <> ''
                GROUP BY criado_por
            ) a ON a.owner_u = u.username
            LEFT JOIN painel_socio_pushinpay sp ON sp.socio_username = u.username
            LEFT JOIN painel_socio_panel_branding pb ON pb.socio_username = u.username
            WHERE u.criado_por IS NULL OR TRIM(u.criado_por) = ''
            ORDER BY u.username
            """
        )
        rows = cursor.fetchall() or []
        out = []
        for r in rows:
            o = dict(r)
            for k in ("pool_limite_gb", "alocado_gb", "disponivel_gb"):
                if k in o and o[k] is not None:
                    o[k] = float(o[k])
            o["pushinpay_socio_ativo"] = bool(o.get("pushinpay_socio_ativo"))
            out.append(o)
        return out
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_socios_topo_para_selecao_dono() -> list[dict]:
    """Usernames de sócios de topo (cargo socio, sem criado_por) — seleção no painel dono."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.username
            FROM usuarios_proxy u
            INNER JOIN painel_cargos c ON u.cargo_id = c.id AND LOWER(TRIM(c.slug)) = 'socio'
            WHERE u.criado_por IS NULL OR TRIM(u.criado_por) = ''
            ORDER BY u.username
            """
        )
        rows = cursor.fetchall() or []
        return [{"username": str(r.get("username") or "").strip()} for r in rows if r.get("username")]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_recarga_payment_logs_for_criados_por(socio_username: str, limit: int = 80) -> list[dict]:
    """Logs de pagamento/recarga onde username é conta criada por `socio_username`."""
    su = (socio_username or "").strip()[:128]
    if not su:
        return []
    lim = max(1, min(200, int(limit)))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT l.id, l.created_at, l.event_type, l.source, l.username, l.pedido_id, l.id_externo, l.meta
            FROM painel_recarga_payment_logs l
            INNER JOIN usuarios_proxy u ON u.username = l.username
            WHERE u.criado_por = %s
            ORDER BY l.id DESC
            LIMIT %s
            """,
            (su, lim),
        )
        return cursor.fetchall() or []
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_usuarios_criados_por(socio_username: str) -> list[dict]:
    socio_username = (socio_username or "").strip()
    if not socio_username:
        return []
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT username, porta, status, limite_gb, usado_bytes, criado_por
            FROM usuarios_proxy
            WHERE criado_por = %s
            ORDER BY username
            """,
            (socio_username,),
        )
        return cursor.fetchall() or []
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def filho_pertence_ao_socio(socio_username: str, child_username: str) -> bool:
    row = get_users((child_username or "").strip())
    if not row:
        return False
    cp = _criado_por_str(row)
    return cp == (socio_username or "").strip()


def sync_porta_filhos_criados_por(socio_username: str, nova_porta: int) -> None:
    socio_username = (socio_username or "").strip()
    if not socio_username:
        return
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_proxy SET porta = %s WHERE criado_por = %s",
            (int(nova_porta), socio_username),
        )
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def usuario_e_socio_responsavel(username: str) -> bool:
    """Sócio de topo: cargo slug «socio» e não foi criado por outro sócio."""
    u = get_user_for_auth((username or "").strip()) or get_users((username or "").strip())
    if not u:
        return False
    if _criado_por_str(u):
        return False
    slug = str(u.get("cargo_slug") or "").strip().lower()
    return slug == "socio"


def socio_username_dono_branding(user_row: dict | None) -> str | None:
    """
    Usuário ao qual associa marca do menu:
    cliente criado por sócio → username do sócio (criado_por); sócio de topo → ele mesmo.
    """
    if not user_row:
        return None
    cp = _criado_por_str(user_row)
    if cp:
        return cp
    slug = str(user_row.get("cargo_slug") or "").strip().lower()
    if slug == "socio":
        ou = str(user_row.get("username") or "").strip()
        return ou if ou else None
    return None


def get_socio_panel_branding(owner_username: str) -> dict | None:
    """Leitura da marca do sócio; None se não houver linha ou tabela inexistente."""
    owner_username = (owner_username or "").strip()
    if not owner_username:
        return None
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT socio_username AS owner_username,
                   titulo_sidebar, subtitulo_sidebar, logo_url
            FROM painel_socio_panel_branding
            WHERE socio_username = %s
            LIMIT 1
            """,
            (owner_username,),
        )
        raw = cursor.fetchone()
        return _normalize_user_row(raw)
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def resolve_panel_branding_payload(user_row: dict | None) -> dict | None:
    owner = socio_username_dono_branding(user_row)
    if not owner:
        return None
    row = get_socio_panel_branding(owner)

    titulo_raw = row.get("titulo_sidebar") if row else None
    subtitulo_raw = row.get("subtitulo_sidebar") if row else None
    logo_raw = row.get("logo_url") if row else None

    def nz(s):
        if s is None:
            return None
        t = str(s).strip()
        return t if t else None

    titulo = nz(titulo_raw)
    subtitulo = nz(subtitulo_raw)
    logo_url = nz(logo_raw)

    if not titulo:
        titulo = owner

    return {
        "titulo_sidebar": titulo,
        "subtitulo_sidebar": subtitulo,
        "logo_url": logo_url,
        "owner_username": owner,
    }


def upsert_socio_panel_branding(
    socio_username: str,
    titulo_sidebar: str | None,
    subtitulo_sidebar: str | None,
    logo_url: str | None,
) -> tuple[bool, str | None]:
    """Após validação externa das strings; valores vazios viram NULL no banco."""
    socio_username = (socio_username or "").strip()
    if not socio_username:
        return False, "Sócio inválido"

    def _nz(s):
        if s is None:
            return None
        t = str(s).strip()
        return t if t else None

    titulo = _nz(titulo_sidebar)
    subtitulo = _nz(subtitulo_sidebar)
    logo = _nz(logo_url)

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_socio_panel_branding
                (socio_username, titulo_sidebar, subtitulo_sidebar, logo_url)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              titulo_sidebar = VALUES(titulo_sidebar),
              subtitulo_sidebar = VALUES(subtitulo_sidebar),
              logo_url = VALUES(logo_url)
            """,
            (socio_username, titulo, subtitulo, logo),
        )
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def update_user_limite_gb(username: str, limite_gb: float) -> tuple[bool, str | None]:
    username = (username or "").strip()
    if not username:
        return False, "Usuário inválido"
    if limite_gb < 0 or limite_gb > 1_000_000:
        return False, "limite_gb fora do intervalo permitido"

    row = get_users(username)
    if not row:
        return False, "Usuário não encontrado"

    cp = _criado_por_str(row)
    if cp:
        outros = sum_limite_gb_criados_por(cp, exceto_username=username)
        parent = get_users(cp)
        if not parent:
            return False, "Responsável da conta não encontrado"
        pool = float(parent.get("limite_gb") or 0)
        if outros + float(limite_gb) > pool + 1e-9:
            return False, "limite_gb ultrapassa o pool disponível do sócio responsável."

    full = get_user_for_auth(username) or row
    slug = str(full.get("cargo_slug") or "").strip().lower()
    if slug == "socio" and not cp:
        soma_filhos = sum_limite_gb_criados_por(username, exceto_username=None)
        if float(limite_gb) + 1e-9 < soma_filhos:
            return (
                False,
                f"limite_gb do sócio não pode ser menor que a soma das cotas dos clientes ({soma_filhos} GB).",
            )

    old_gb = float(row.get("limite_gb") or 0)
    new_gb = float(limite_gb)
    aumentou_gb = new_gb > old_gb + 1e-9

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        if aumentou_gb:
            # Igual à recarga PIX: acréscimo de GB volta a contar na ARE CEO (mantém baseline).
            cursor.execute(
                """
                UPDATE usuarios_proxy
                SET limite_gb = %s, custo_pago = 0
                WHERE username = %s
                """,
                (new_gb, username),
            )
        else:
            cursor.execute(
                "UPDATE usuarios_proxy SET limite_gb = %s WHERE username = %s",
                (new_gb, username),
            )
        ok = cursor.rowcount >= 1
        conn.commit()
        return (ok, None) if ok else (False, "Usuário não encontrado")
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def set_user_cargo(username: str, cargo_id: int | None) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_proxy SET cargo_id = %s WHERE username = %s",
            (cargo_id, username),
        )
        ok = cursor.rowcount >= 1
        conn.commit()
        return ok
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def update_user_admin_fields(
    current_username: str,
    new_username: str | None = None,
    new_senha: str | None = None,
    new_porta: int | None = None,
) -> tuple[bool, str | None]:
    """Atualiza campos principais do usuário pelo admin."""
    current_username = (current_username or "").strip()
    if not current_username:
        return False, "Usuário inválido"

    target_username = (new_username or current_username).strip()
    if not target_username or len(target_username) > 128:
        return False, "Username inválido"
    if target_username != current_username and username_exists(target_username):
        return False, "Username já existe"

    senha_to_set: str | None = None
    if new_senha is not None:
        senha_to_set = str(new_senha)
        if len(senha_to_set) < 4:
            return False, "Senha muito curta (mínimo 4 caracteres)"

    porta_to_set: int | None = None
    if new_porta is not None:
        from cpa_panel.gateway_ports import is_allowed_port

        try:
            porta_to_set = int(new_porta)
        except (TypeError, ValueError):
            return False, "Porta inválida"
        if not is_allowed_port(porta_to_set):
            return False, "Porta deve ser 823 (HTTP) ou 824 (SOCKS5)"

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        sets: list[str] = []
        params: list = []
        if target_username != current_username:
            sets.append("username = %s")
            params.append(target_username)
        if senha_to_set is not None:
            sets.append("senha = %s")
            params.append(senha_to_set)
        if porta_to_set is not None:
            sets.append("porta = %s")
            params.append(porta_to_set)
        if not sets:
            return False, "Nenhum campo para atualizar"

        params.append(current_username)
        cursor.execute(f"UPDATE usuarios_proxy SET {', '.join(sets)} WHERE username = %s", tuple(params))
        if cursor.rowcount < 1:
            conn.rollback()
            return False, "Usuário não encontrado"
        try:
            if target_username != current_username:
                cursor.execute(
                    "UPDATE usuarios_proxy SET criado_por=%s WHERE criado_por=%s",
                    (target_username, current_username),
                )
            if porta_to_set is not None:
                cursor.execute(
                    "UPDATE usuarios_proxy SET porta=%s WHERE criado_por=%s",
                    (int(porta_to_set), target_username),
                )
        except Exception:
            pass
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def count_proxy_logs_all(
    username_filter: str | None = None,
    created_after=None,
    created_before_exclusive=None,
) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = []
        params: list = []
        if username_filter:
            wheres.append("username = %s")
            params.append(username_filter)
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        cursor.execute(f"SELECT COUNT(*) AS c FROM proxy_access_logs {where_sql}", tuple(params))
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    finally:
        cursor.close()
        conn.close()


def list_proxy_logs_all(
    limit: int = 100,
    offset: int = 0,
    username_filter: str | None = None,
    created_after=None,
    created_before_exclusive=None,
):
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = []
        params: list = []
        if username_filter:
            wheres.append("username = %s")
            params.append(username_filter)
        if created_after is not None:
            wheres.append("created_at >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("created_at < %s")
            params.append(created_before_exclusive)
        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        params.extend([limit, offset])
        cursor.execute(
            f"""
                SELECT id, username, porta, dest_host, dest_display, method,
                       bytes_upload, bytes_download, upstream_proxy, created_at
                FROM proxy_access_logs
                {where_sql}
                ORDER BY id DESC
                LIMIT %s OFFSET %s
                """,
            tuple(params),
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def list_cargos_with_permissions():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, slug, nome, bypass_all
            FROM painel_cargos
            ORDER BY id
            """
        )
        cargos = cursor.fetchall()
        out = []
        for c in cargos:
            cid = int(c["id"])
            cursor.execute(
                """
                SELECT permission_code AS code
                FROM painel_cargo_permissoes
                WHERE cargo_id = %s
                ORDER BY permission_code
                """,
                (cid,),
            )
            perms = [r["code"] for r in cursor.fetchall()]
            row = dict(c)
            row["permissions"] = perms
            out.append(row)
        return out
    finally:
        cursor.close()
        conn.close()


def get_cargo_by_slug(slug: str):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, slug, nome, bypass_all FROM painel_cargos WHERE slug = %s LIMIT 1",
            (slug,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def get_cargo_by_id(cargo_id: int):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, slug, nome, bypass_all FROM painel_cargos WHERE id = %s LIMIT 1",
            (int(cargo_id),),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def create_cargo(slug: str, nome: str, bypass_all: int = 0) -> int | None:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_cargos (slug, nome, bypass_all)
            VALUES (%s, %s, %s)
            """,
            (slug, nome, int(bypass_all)),
        )
        conn.commit()
        return int(cursor.lastrowid) if cursor.lastrowid else None
    except Exception:
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()


def update_cargo_meta(cargo_id: int, nome: str) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE painel_cargos SET nome = %s WHERE id = %s AND slug NOT IN ('dono', 'cliente')",
            (nome, int(cargo_id)),
        )
        ok = cursor.rowcount >= 1
        conn.commit()
        return ok
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def replace_cargo_permissions(cargo_id: int, codes: list[str]) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT slug, bypass_all FROM painel_cargos WHERE id = %s LIMIT 1",
            (int(cargo_id),),
        )
        row = cursor.fetchone()
        if not row:
            return False
        if row["slug"] in ("dono", "cliente"):
            return False
        if int(row["bypass_all"] or 0) == 1:
            return True
        cursor.execute("DELETE FROM painel_cargo_permissoes WHERE cargo_id = %s", (int(cargo_id),))
        for code in codes:
            try:
                cursor.execute(
                    """
                    INSERT INTO painel_cargo_permissoes (cargo_id, permission_code)
                    VALUES (%s, %s)
                    """,
                    (int(cargo_id), str(code)),
                )
            except Exception:
                pass
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def count_users_with_cargo(cargo_id: int) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT COUNT(*) AS c FROM usuarios_proxy WHERE cargo_id = %s",
            (int(cargo_id),),
        )
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    finally:
        cursor.close()
        conn.close()


def get_cargo_id_by_slug(slug: str) -> int | None:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM painel_cargos WHERE slug = %s LIMIT 1",
            (slug,),
        )
        row = cursor.fetchone()
        return int(row["id"]) if row else None
    finally:
        cursor.close()
        conn.close()


def username_exists(username: str) -> bool:
    return get_users(username) is not None


_ALPHANUM_LOWER = string.ascii_lowercase + string.digits
_ALPHANUM_MIXED = string.ascii_letters + string.digits


def random_filho_socio_username() -> str:
    """Username aleatório curto único para contas criadas pelo sócio (prefixo fixo sx)."""
    for _ in range(80):
        body = ''.join(secrets.choice(_ALPHANUM_LOWER) for _ in range(12))
        u = f"sx{body}"
        if len(u) <= 128 and not username_exists(u):
            return u
    raise RuntimeError("Não foi possível gerar username único")


def random_filho_socio_password(length: int = 14) -> str:
    """Senha aleatória (somente ASCII alfanumérico, sem dois-pontos) para uso em linha host:porta:user:pass."""
    ln = max(8, min(int(length), 64))
    return ''.join(secrets.choice(_ALPHANUM_MIXED) for _ in range(ln))


def _filho_socio_execute_insert_once(
    cursor,
    *,
    username: str,
    socio_username: str,
    senha: str,
    porta: int,
    limite_gb: float,
    cid: int,
    br_id: int | None,
) -> tuple[bool, str | None]:
    """Um INSERT bem-sucedido no mesmo estilo de create_usuario_filho_socio; sem COMMIT."""
    if br_id is not None:
        attempts = (
            (
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em, pais_id)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
            ),
            (
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at, pais_id)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
            ),
            (
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, pais_id)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s, %s)
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
            ),
        )
        for sql, params in attempts:
            try:
                cursor.execute(sql, params)
                return True, None
            except Exception:
                continue
        return False, "Erro ao inserir conta (estrutura do banco / coluna criado_por)"

    attempts = (
        (
            """
            INSERT INTO usuarios_proxy
                (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em)
            VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW())
            """,
            (username, socio_username, senha, int(porta), float(limite_gb), cid),
        ),
        (
            """
            INSERT INTO usuarios_proxy
                (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at)
            VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW())
            """,
            (username, socio_username, senha, int(porta), float(limite_gb), cid),
        ),
        (
            """
            INSERT INTO usuarios_proxy
                (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id)
            VALUES (%s, %s, %s, %s, 1, %s, 0, %s)
            """,
            (username, socio_username, senha, int(porta), float(limite_gb), cid),
        ),
    )
    for sql, params in attempts:
        try:
            cursor.execute(sql, params)
            return True, None
        except Exception:
            continue
    return False, "Erro ao inserir conta (estrutura do banco)"


SOCIO_CREATE_BULK_CAP = 200


def bulk_create_filhos_socio_aleatorio(
    socio_username: str,
    quantidade: int,
    limite_gb_cada: float,
    porta_informada: int,
) -> tuple[bool, str | None, list[dict]]:
    """
    Cria ``quantidade`` contas cliente com usuário/senha aleatórios, mesma ``porta`` do sócio.
    ``porta_informada`` deve coincidir com a porta atual do sócio (confirmação no painel).
    Retorna lista de dicts com username e senha.
    """
    from cpa_panel.gateway_ports import is_allowed_port

    socio_username = (socio_username or "").strip()
    if not socio_username:
        return False, "Sócio inválido", []
    qtd = int(quantidade)
    if qtd < 1 or qtd > SOCIO_CREATE_BULK_CAP:
        return False, f"quantidade deve ser entre 1 e {SOCIO_CREATE_BULK_CAP}", []
    try:
        limite_gb_each = float(limite_gb_cada)
    except (TypeError, ValueError):
        return False, "limite_gb inválido", []
    if limite_gb_each <= 0 or limite_gb_each > 1_000_000:
        return False, "limite_gb fora do intervalo permitido", []

    parent = get_user_for_auth(socio_username) or get_users(socio_username)
    if not parent:
        return False, "Sócio não encontrado", []
    if _criado_por_str(parent):
        return False, "Esta conta não pode criar usuários por sócio.", []
    slug = str(parent.get("cargo_slug") or "").strip().lower()
    if slug != "socio":
        return False, "Apenas contas com cargo Sócio podem usar esta função.", []

    porta_socio = int(parent["porta"])
    try:
        p_inf = int(porta_informada)
    except (TypeError, ValueError):
        return False, "porta inválida", []
    if not is_allowed_port(p_inf):
        return False, "Porta deve ser 823 (HTTP) ou 824 (SOCKS5)", []
    if p_inf != porta_socio:
        return (
            False,
            f"A porta selecionada ({p_inf}) deve ser igual à porta do seu gateway nas configurações ({porta_socio}).",
            [],
        )
    porta = porta_socio

    pool = float(parent.get("limite_gb") or 0)
    ja = sum_limite_gb_criados_por(socio_username, exceto_username=None)
    need = qtd * limite_gb_each
    if ja + need > pool + 1e-9:
        disp = max(0.0, pool - ja)
        return (
            False,
            f"Cota insuficiente no pool: precisa de {need} GB ({qtd} × {limite_gb_each} GB), disponível ~{disp:.4f} GB.",
            [],
        )

    cid = get_cargo_id_by_slug("cliente")
    if cid is None:
        return False, "Cargo «cliente» não encontrado.", []
    br_id = get_pais_id_brasil()

    conn = conexao_bd()
    cursor = conn.cursor()
    created: list[dict] = []
    try:
        conn.autocommit = False
        for _ in range(qtd):
            username = random_filho_socio_username()
            senha = random_filho_socio_password()
            ok_ins, err_ins = _filho_socio_execute_insert_once(
                cursor,
                username=username,
                socio_username=socio_username,
                senha=senha,
                porta=porta,
                limite_gb=limite_gb_each,
                cid=int(cid),
                br_id=br_id,
            )
            if not ok_ins or err_ins:
                conn.rollback()
                return False, err_ins or "Falha ao criar uma das contas", []
            created.append({"username": username, "senha": senha})
        conn.commit()
        return True, None, created
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        return False, str(e), []
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def porta_em_uso(porta: int, exceto_username: str | None = None) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        if exceto_username:
            cursor.execute(
                "SELECT username FROM usuarios_proxy WHERE porta = %s AND username <> %s LIMIT 1",
                (int(porta), exceto_username),
            )
        else:
            cursor.execute(
                "SELECT username FROM usuarios_proxy WHERE porta = %s LIMIT 1",
                (int(porta),),
            )
        return cursor.fetchone() is not None
    finally:
        cursor.close()
        conn.close()


def create_usuario_filho_socio(
    socio_username: str,
    username: str,
    senha: str,
    limite_gb: float,
) -> tuple[bool, str | None]:
    """
    Cria cliente «normal» sob o pool de GB do sócio, com a mesma porta (gateway) do sócio.
    Requer coluna usuarios_proxy.criado_por (sql/usuarios_proxy_criado_por.sql).
    """
    from cpa_panel.gateway_ports import is_allowed_port

    socio_username = (socio_username or "").strip()
    username = (username or "").strip()
    senha = senha or ""
    if not socio_username or not username or len(username) > 128:
        return False, "Username inválido"
    if len(senha) < 4:
        return False, "Senha muito curta (mínimo 4 caracteres)"
    if limite_gb < 0 or limite_gb > 1_000_000:
        return False, "limite_gb inválido"
    if username_exists(username):
        return False, "Usuário já existe"

    parent = get_user_for_auth(socio_username) or get_users(socio_username)
    if not parent:
        return False, "Sócio não encontrado"
    if _criado_por_str(parent):
        return False, "Esta conta não pode criar usuários por sócio."
    slug = str(parent.get("cargo_slug") or "").strip().lower()
    if slug != "socio":
        return False, "Apenas contas com cargo Sócio podem usar esta função."

    porta = int(parent["porta"])
    if not is_allowed_port(porta):
        return False, "Porta do sócio inválida para o gateway"

    pool = float(parent.get("limite_gb") or 0)
    ja = sum_limite_gb_criados_por(socio_username, exceto_username=None)
    if ja + float(limite_gb) > pool + 1e-9:
        return (
            False,
            f"Cota excede o pool disponível ({pool} GB; já alocado ~{ja} GB).",
        )

    cid = get_cargo_id_by_slug("cliente")
    br_id = get_pais_id_brasil()

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        if br_id is not None:
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy
                        (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em, pais_id)
                    VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                    """,
                    (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy
                        (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at, pais_id)
                    VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                    """,
                    (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy
                        (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, pais_id)
                    VALUES (%s, %s, %s, %s, 1, %s, 0, %s, %s)
                    """,
                    (username, socio_username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()

        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW())
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception:
            conn.rollback()
        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s, NOW())
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception:
            conn.rollback()
        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy
                    (username, criado_por, senha, porta, status, limite_gb, usado_bytes, cargo_id)
                VALUES (%s, %s, %s, %s, 1, %s, 0, %s)
                """,
                (username, socio_username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception as e:
            conn.rollback()
            return False, str(e)
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def create_usuario_proxy(
    username: str,
    senha: str,
    porta: int,
    limite_gb: float,
    cargo_id: int | None,
) -> tuple[bool, str | None]:
    from cpa_panel.gateway_ports import is_allowed_port

    username = (username or "").strip()
    senha = senha or ""
    if not username or len(username) > 128:
        return False, "Username inválido"
    if len(senha) < 4:
        return False, "Senha muito curta (mínimo 4 caracteres)"
    if not is_allowed_port(porta):
        return False, "Porta deve ser 823 (HTTP) ou 824 (SOCKS5)"
    if limite_gb < 0 or limite_gb > 1_000_000:
        return False, "limite_gb inválido"
    if username_exists(username):
        return False, "Usuário já existe"

    cid = cargo_id
    if cid is None:
        cid = get_cargo_id_by_slug("cliente")

    br_id = get_pais_id_brasil()

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        if br_id is not None:
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em, pais_id)
                    VALUES (%s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                    """,
                    (username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at, pais_id)
                    VALUES (%s, %s, %s, 1, %s, 0, %s, NOW(), %s)
                    """,
                    (username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()
            try:
                cursor.execute(
                    """
                    INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id, pais_id)
                    VALUES (%s, %s, %s, 1, %s, 0, %s, %s)
                    """,
                    (username, senha, int(porta), float(limite_gb), cid, br_id),
                )
                conn.commit()
                return True, None
            except Exception:
                conn.rollback()

        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id, criado_em)
                VALUES (%s, %s, %s, 1, %s, 0, %s, NOW())
                """,
                (username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception:
            conn.rollback()
        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id, created_at)
                VALUES (%s, %s, %s, 1, %s, 0, %s, NOW())
                """,
                (username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception:
            conn.rollback()
        try:
            cursor.execute(
                """
                INSERT INTO usuarios_proxy (username, senha, porta, status, limite_gb, usado_bytes, cargo_id)
                VALUES (%s, %s, %s, 1, %s, 0, %s)
                """,
                (username, senha, int(porta), float(limite_gb), cid),
            )
            conn.commit()
            return True, None
        except Exception as e:
            conn.rollback()
            return False, str(e)
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def list_recarga_precos_ativos():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, titulo, gb_credito, preco_reais, ordem
            FROM painel_recarga_precos
            WHERE ativo = 1
            ORDER BY ordem ASC, id ASC
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def get_recarga_por_gb_config() -> dict:
    """Preço por GB e limites para recarga PIX (linha id=1 em painel_recarga_config)."""
    defaults = {
        "preco_por_gb_reais": 9.90,
        "gb_min": 1.0,
        "gb_max": 500.0,
        "gb_step": 1.0,
    }
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT preco_por_gb_reais, gb_min, gb_max, gb_step
            FROM painel_recarga_config
            WHERE id = 1
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if not row:
            return defaults
        return {
            "preco_por_gb_reais": float(row["preco_por_gb_reais"]),
            "gb_min": float(row["gb_min"]),
            "gb_max": float(row["gb_max"]),
            "gb_step": float(row["gb_step"] or 1),
        }
    except Exception:
        return defaults
    finally:
        cursor.close()
        conn.close()


def list_recarga_descontos_para_calculo():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, nome, gb_minimo, percentual_desconto, valor_fixo_reais, ativo, ordem
            FROM painel_recarga_descontos
            WHERE ativo = 1
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_recarga_descontos_admin():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, nome, gb_minimo, percentual_desconto, valor_fixo_reais, ativo, ordem,
                   created_at, updated_at
            FROM painel_recarga_descontos
            ORDER BY gb_minimo DESC, ordem ASC, id DESC
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def get_recarga_desconto_by_id(did: int):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, nome, gb_minimo, percentual_desconto, valor_fixo_reais, ativo, ordem
            FROM painel_recarga_descontos
            WHERE id = %s
            LIMIT 1
            """,
            (int(did),),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def create_recarga_desconto(
    nome: str,
    gb_minimo: float,
    percentual_desconto: float | None,
    valor_fixo_reais: float | None,
    ativo: int,
    ordem: int,
) -> int | None:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_recarga_descontos
              (nome, gb_minimo, percentual_desconto, valor_fixo_reais, ativo, ordem)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (nome[:160], float(gb_minimo), percentual_desconto, valor_fixo_reais, int(ativo), int(ordem)),
        )
        conn.commit()
        return int(cursor.lastrowid) if cursor.lastrowid else None
    except Exception:
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()


def update_recarga_desconto_fields(did: int, fields: dict) -> bool:
    allowed = {"nome", "gb_minimo", "percentual_desconto", "valor_fixo_reais", "ativo", "ordem"}
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM painel_recarga_descontos WHERE id = %s LIMIT 1",
            (int(did),),
        )
        if not cursor.fetchone():
            return False
        parts = []
        vals = []
        for key in allowed:
            if key not in fields:
                continue
            parts.append(f"{key} = %s")
            vals.append(fields[key])
        if not parts:
            return True
        vals.append(int(did))
        sql = f"UPDATE painel_recarga_descontos SET {', '.join(parts)} WHERE id = %s"
        cursor.execute(sql, vals)
        conn.commit()
        return cursor.rowcount >= 1
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def delete_recarga_desconto(did: int) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM painel_recarga_descontos WHERE id = %s", (int(did),))
        conn.commit()
        return cursor.rowcount >= 1
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def delete_cargo_if_allowed(cargo_id: int) -> tuple[bool, str | None]:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, slug FROM painel_cargos WHERE id = %s LIMIT 1",
            (int(cargo_id),),
        )
        row = cursor.fetchone()
        if not row:
            return False, "Cargo não encontrado"
        if row["slug"] in ("dono", "cliente", "tudo"):
            return False, "Este cargo não pode ser removido"
        cursor.execute(
            "SELECT COUNT(*) AS c FROM usuarios_proxy WHERE cargo_id = %s",
            (int(cargo_id),),
        )
        n = int(cursor.fetchone()["c"])
        if n > 0:
            return False, "Existem usuários com este cargo"
        cursor.execute("DELETE FROM painel_cargos WHERE id = %s", (int(cargo_id),))
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


# --- PushinPay: config global (painel_pushinpay_config) + sócio (painel_socio_pushinpay) ---


def get_pushinpay_config_row() -> dict | None:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, api_base, api_token, site_public_url, webhook_secret, webhook_header,
                   webhook_require_secret, recarga_pix_max_per_hour, atualizado_em
            FROM painel_pushinpay_config
            WHERE id = 1
            LIMIT 1
            """,
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def update_pushinpay_config_fields(fields: dict) -> tuple[bool, str | None]:
    """Atualiza apenas chaves presentes em `fields` (snake_case como no banco)."""
    allowed = {
        "api_base",
        "api_token",
        "site_public_url",
        "webhook_secret",
        "webhook_header",
        "webhook_require_secret",
        "recarga_pix_max_per_hour",
    }
    parts: list[str] = []
    params: list = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k == "webhook_require_secret":
            parts.append("webhook_require_secret = %s")
            params.append(1 if v else 0)
        elif k == "recarga_pix_max_per_hour":
            parts.append("recarga_pix_max_per_hour = %s")
            params.append(int(v))
        else:
            parts.append(f"{k} = %s")
            params.append(v)
    if not parts:
        return True, None
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        sql = f"UPDATE painel_pushinpay_config SET {', '.join(parts)} WHERE id = 1"
        cursor.execute(sql, tuple(params))
        conn.commit()
        return True, None
    except mysql.connector.Error as e:
        conn.rollback()
        return False, str(e)[:400]
    except Exception as e:
        conn.rollback()
        return False, str(e)[:400]
    finally:
        cursor.close()
        conn.close()


def get_socio_pushinpay(socio_username: str) -> dict | None:
    socio_username = (socio_username or "").strip()
    if not socio_username:
        return None
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT socio_username, api_base, api_token, webhook_secret, atualizado_em
            FROM painel_socio_pushinpay
            WHERE socio_username = %s
            LIMIT 1
            """,
            (socio_username[:128],),
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def upsert_socio_pushinpay(
    socio_username: str,
    api_token: str,
    webhook_secret: str | None,
    api_base: str | None,
) -> tuple[bool, str | None]:
    socio_username = (socio_username or "").strip()[:128]
    tok = (api_token or "").strip()
    if not socio_username or not tok:
        return False, "api_token obrigatório"
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        wb = (webhook_secret or "").strip() or None
        ab = (api_base or "").strip() or None
        cursor.execute(
            """
            INSERT INTO painel_socio_pushinpay (socio_username, api_base, api_token, webhook_secret)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              api_base = VALUES(api_base),
              api_token = VALUES(api_token),
              webhook_secret = VALUES(webhook_secret)
            """,
            (socio_username, ab, tok, wb),
        )
        conn.commit()
        return True, None
    except mysql.connector.Error as e:
        conn.rollback()
        if getattr(e, "errno", None) == 1146:
            return False, "Execute sql/painel_socio_pushinpay.sql no banco."
        return False, str(e)[:400]
    except Exception as e:
        conn.rollback()
        return False, str(e)[:400]
    finally:
        cursor.close()
        conn.close()


def delete_socio_pushinpay(socio_username: str) -> bool:
    socio_username = (socio_username or "").strip()[:128]
    if not socio_username:
        return False
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM painel_socio_pushinpay WHERE socio_username = %s", (socio_username,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


# --- Recarga PIX (PushinPay) / painel_recarga_pedidos_pix -----------------


def _mysql_pedido_pix_err_msg(exc: mysql.connector.Error) -> str:
    code = getattr(exc, "errno", None)
    raw = (getattr(exc, "msg", None) or str(exc)).strip()
    if code == 1146:
        return "Tabela painel_recarga_pedidos_pix não existe. Execute o arquivo sql/painel_recarga_pedidos_pix.sql no banco."
    if code == 1054:
        return f"Estrutura da tabela incompatível (coluna): {raw}"
    if code == 1406:
        return (
            "Campo payload_pix (ou outro) muito curto no MySQL. O código PIX copia-e-cola é longo. "
            "Execute sql/painel_recarga_pedidos_pix_fix.sql (altera payload_pix para MEDIUMTEXT)."
        )
    if code in (1048, 1364):
        return (
            "Coluna obrigatória sem valor (ex.: preco_id NOT NULL na recarga por GB). "
            "Execute sql/painel_recarga_pedidos_pix_fix.sql para permitir preco_id NULL."
        )
    if code == 1062:
        return f"ID externo duplicado (já existe pedido com este id_externo): {raw}"
    return raw[:400] if raw else "Erro ao gravar pedido no MySQL"


def get_recarga_preco_ativo_by_id(pid: int):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, titulo, gb_credito, preco_reais, ativo
            FROM painel_recarga_precos
            WHERE id = %s AND ativo = 1
            LIMIT 1
            """,
            (int(pid),),
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def insert_recarga_pedido_pix(
    username: str,
    preco_id: int | None,
    gb_credito: float,
    valor_reais: float,
    id_externo: str,
    payload_pix: str,
    pushinpay_source: str = "global",
    socio_billing_username: str | None = None,
) -> tuple[int | None, str | None]:
    """Retorna (id_local, None) ou (None, mensagem de erro)."""
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        pix_payload = payload_pix if isinstance(payload_pix, str) else str(payload_pix)
        src = (pushinpay_source or "global").strip().lower()[:16]
        if src not in ("global", "socio"):
            src = "global"
        socio_b = None
        if src == "socio" and socio_billing_username:
            socio_b = str(socio_billing_username).strip()[:128] or None
        cursor.execute(
            """
            INSERT INTO painel_recarga_pedidos_pix
              (username, preco_id, gb_credito, valor_reais, status, id_externo, payload_pix,
               pushinpay_source, socio_billing_username)
            VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s, %s)
            """,
            (
                username[:128],
                int(preco_id) if preco_id is not None else None,
                float(gb_credito),
                float(valor_reais),
                id_externo[:80],
                pix_payload,
                src,
                socio_b,
            ),
        )
        conn.commit()
        lid = cursor.lastrowid
        if lid:
            return int(lid), None
        cursor.execute("SELECT LAST_INSERT_ID() AS x")
        row = cursor.fetchone()
        if row and row[0]:
            return int(row[0]), None
        return None, "INSERT ok mas LAST_INSERT_ID indisponível — verifique AUTO_INCREMENT na tabela"
    except mysql.connector.Error as e:
        conn.rollback()
        return None, _mysql_pedido_pix_err_msg(e)
    except Exception as e:
        conn.rollback()
        return None, str(e)[:400]
    finally:
        cursor.close()
        conn.close()


def list_recarga_pedidos_pix_for_user(username: str, limit: int = 30):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, preco_id, gb_credito, valor_reais, status, id_externo, pushinpay_source,
                   socio_billing_username, criado_em, atualizado_em
            FROM painel_recarga_pedidos_pix
            WHERE username = %s
            ORDER BY id DESC
            LIMIT %s
            """,
            (username, int(limit)),
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_recarga_pedidos_pix_for_socio_network(
    socio_username: str,
    limit: int = 50,
    offset: int = 0,
    created_after=None,
    created_before_exclusive=None,
):
    """Pedidos PIX de recarga: conta do próprio sócio + contas com criado_por = sócio."""
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    su = str(socio_username or "").strip()
    if not su:
        return []
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = [
            "(p.username = %s OR EXISTS (SELECT 1 FROM usuarios_proxy u "
            "WHERE u.username = p.username AND TRIM(IFNULL(u.criado_por,'')) = %s))"
        ]
        params: list = [su, su]
        if created_after is not None:
            wheres.append("p.criado_em >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("p.criado_em < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        params.extend([limit, offset])
        cursor.execute(
            f"""
            SELECT p.id, p.username, p.preco_id, p.gb_credito, p.valor_reais, p.status, p.id_externo,
                   p.pushinpay_source, p.socio_billing_username, p.criado_em, p.atualizado_em
            FROM painel_recarga_pedidos_pix p
            {where_sql}
            ORDER BY p.id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params),
        )
        return cursor.fetchall() or []
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def count_recarga_pedidos_pix_for_socio_network(
    socio_username: str,
    created_after=None,
    created_before_exclusive=None,
) -> int:
    su = str(socio_username or "").strip()
    if not su:
        return 0
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        wheres = [
            "(p.username = %s OR EXISTS (SELECT 1 FROM usuarios_proxy u "
            "WHERE u.username = p.username AND TRIM(IFNULL(u.criado_por,'')) = %s))"
        ]
        params: list = [su, su]
        if created_after is not None:
            wheres.append("p.criado_em >= %s")
            params.append(created_after)
        if created_before_exclusive is not None:
            wheres.append("p.criado_em < %s")
            params.append(created_before_exclusive)
        where_sql = "WHERE " + " AND ".join(wheres)
        cursor.execute(
            f"SELECT COUNT(*) AS c FROM painel_recarga_pedidos_pix p {where_sql}",
            tuple(params),
        )
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        cursor.close()
        conn.close()


def get_pedido_pix_by_id_for_user(pedido_id: int, username: str):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, username, preco_id, gb_credito, valor_reais, status, id_externo, payload_pix,
                   pushinpay_source, socio_billing_username, criado_em, atualizado_em
            FROM painel_recarga_pedidos_pix
            WHERE id = %s AND username = %s
            LIMIT 1
            """,
            (int(pedido_id), username),
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def get_pedido_pix_by_external_id(id_externo: str):
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, username, preco_id, gb_credito, valor_reais, status, id_externo, payload_pix,
                   pushinpay_source, socio_billing_username, criado_em, atualizado_em
            FROM painel_recarga_pedidos_pix
            WHERE id_externo = %s
            LIMIT 1
            """,
            (id_externo[:80],),
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def _decimal_centavos_from_reais(valor_reais) -> int:
    from decimal import ROUND_HALF_UP, Decimal

    d = Decimal(str(valor_reais))
    return int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def finalize_pix_pedido_from_gateway(
    id_externo: str,
    remote_status: str,
    value_cents_remote: int | None,
) -> str:
    """
    Idempotente. Retorna:
      not_found, duplicate_paid, value_mismatch, credited, updated_nonpaid,
      invalid_transition, error
    """
    id_externo = (id_externo or "").strip()
    if not id_externo:
        return "not_found"

    st = (remote_status or "").lower().strip()
    if st == "cancelled":
        st = "canceled"

    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("START TRANSACTION")
        cursor.execute(
            """
            SELECT id, username, preco_id, gb_credito, valor_reais, status, id_externo,
                   pushinpay_source, socio_billing_username
            FROM painel_recarga_pedidos_pix
            WHERE id_externo = %s
            FOR UPDATE
            """,
            (id_externo[:80],),
        )
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            return "not_found"

        expected_cents = _decimal_centavos_from_reais(row["valor_reais"])
        cur = (row["status"] or "").lower()

        if st == "paid":
            if value_cents_remote is None:
                conn.rollback()
                return "missing_value"
            if int(value_cents_remote) != int(expected_cents):
                conn.rollback()
                return "value_mismatch"
            if cur == "paid":
                conn.commit()
                return "duplicate_paid"
            if cur != "pending":
                conn.rollback()
                return "invalid_transition"
            delta_gb = float(row["gb_credito"] or 0)
            if delta_gb <= 0:
                conn.rollback()
                return "error"

            cursor.execute(
                """
                SELECT username, limite_gb, criado_por
                FROM usuarios_proxy
                WHERE username = %s
                LIMIT 1
                """,
                (str(row["username"] or "").strip()[:128],),
            )
            ux = cursor.fetchone()
            cp_f = _criado_por_str(ux)
            if cp_f:
                cp_key = (cp_f or "").strip()[:128]
                cursor.execute(
                    """
                    SELECT COALESCE(SUM(CAST(limite_gb AS DECIMAL(24, 8))), 0) AS s
                    FROM usuarios_proxy
                    WHERE criado_por = %s
                    """,
                    (cp_key,),
                )
                ar = cursor.fetchone()
                alloc = float(ar["s"] or 0) if ar else 0.0
                cursor.execute(
                    """
                    SELECT CAST(limite_gb AS DECIMAL(24, 8)) AS lim
                    FROM usuarios_proxy
                    WHERE username = %s
                    LIMIT 1
                    """,
                    (cp_key,),
                )
                sw = cursor.fetchone()
                pool = float(sw["lim"] or 0) if sw else 0.0
                if alloc + delta_gb > pool + 1e-4:
                    conn.rollback()
                    try:
                        insert_recarga_payment_log(
                            "pix_finalize_pool_blocked",
                            "system",
                            username=str(row["username"] or ""),
                            pedido_id=int(row["id"]),
                            id_externo=id_externo[:80],
                            meta={
                                "socio": cp_key,
                                "alloc_gb": alloc,
                                "pool_limite_gb": pool,
                                "delta_gb": delta_gb,
                            },
                        )
                    except Exception:
                        pass
                    return "pool_blocked"

            cursor.execute(
                """
                UPDATE painel_recarga_pedidos_pix
                SET status = 'paid', atualizado_em = CURRENT_TIMESTAMP
                WHERE id = %s AND status = 'pending'
                """,
                (int(row["id"]),),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                return "invalid_transition"
            # Recarga efetivada: volta a contar na ARE CEO (valorização) — zera custo_pago marcado manualmente.
            cursor.execute(
                """
                UPDATE usuarios_proxy
                SET limite_gb = LEAST(limite_gb + %s, 1000000),
                    custo_pago = 0
                WHERE username = %s
                """,
                (delta_gb, row["username"]),
            )
            conn.commit()
            return "credited"

        if value_cents_remote is not None and int(value_cents_remote) != int(expected_cents):
            conn.rollback()
            return "value_mismatch"

        if st in ("canceled", "expired"):
            if cur == "paid":
                conn.rollback()
                return "invalid_transition"
            if cur == "pending":
                new_status = "expired" if st == "expired" else "canceled"
                cursor.execute(
                    """
                    UPDATE painel_recarga_pedidos_pix
                    SET status = %s, atualizado_em = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (new_status, int(row["id"])),
                )
            conn.commit()
            return "updated_nonpaid"

        conn.commit()
        return "updated_nonpaid"
    except Exception:
        conn.rollback()
        return "error"
    finally:
        cursor.close()
        conn.close()


def insert_recarga_payment_log(
    event_type: str,
    source: str,
    *,
    username: str | None = None,
    pedido_id: int | None = None,
    id_externo: str | None = None,
    meta: dict | None = None,
) -> None:
    """Registro best-effort; falhas não interrompem fluxo de pagamento."""
    try:
        meta_s = None
        if meta is not None:
            meta_s = json.dumps(meta, ensure_ascii=False, default=str)
            if len(meta_s) > 60000:
                meta_s = meta_s[:60000] + "…"
        ext = (id_externo or "").strip()[:80] or None
        uname = (username or "").strip()[:128] or None
        conn = conexao_bd()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO painel_recarga_payment_logs
                  (event_type, source, username, pedido_id, id_externo, meta)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    (event_type or "")[:80],
                    (source or "")[:32],
                    uname,
                    int(pedido_id) if pedido_id is not None else None,
                    ext,
                    meta_s,
                ),
            )
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        _logger_payment.warning("insert_recarga_payment_log ignorado: %s", e)


def _payment_logs_where_params(
    username_filter: str | None = None,
    created_after=None,
    created_before_exclusive=None,
) -> tuple[str, list]:
    """Cláusula WHERE (prefixo l.) e parâmetros para listagem e contagem de logs PIX."""
    uf = (username_filter or "").strip()
    wheres = []
    params: list = []
    if uf:
        like = f"%{uf}%"
        wheres.append(
            "("
            "l.username LIKE %s OR CAST(l.pedido_id AS CHAR) LIKE %s OR l.id_externo LIKE %s OR "
            "EXISTS (SELECT 1 FROM painel_recarga_pedidos_pix px WHERE px.id = l.pedido_id AND px.username LIKE %s) OR "
            "EXISTS (SELECT 1 FROM painel_recarga_pedidos_pix px2 WHERE px2.id_externo = l.id_externo AND px2.username LIKE %s)"
            ")"
        )
        params.extend([like, like, like, like, like])
    if created_after is not None:
        wheres.append("l.created_at >= %s")
        params.append(created_after)
    if created_before_exclusive is not None:
        wheres.append("l.created_at < %s")
        params.append(created_before_exclusive)
    where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
    return where_sql, params


def count_recarga_payment_logs_all(
    username_filter: str | None = None,
    created_after=None,
    created_before_exclusive=None,
) -> int:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        where_sql, params = _payment_logs_where_params(username_filter, created_after, created_before_exclusive)
        cursor.execute(
            f"SELECT COUNT(*) AS c FROM painel_recarga_payment_logs l {where_sql}",
            tuple(params),
        )
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        cursor.close()
        conn.close()


def list_recarga_payment_logs_all(
    limit: int = 50,
    offset: int = 0,
    username_filter: str | None = None,
    created_after=None,
    created_before_exclusive=None,
):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        where_sql, params = _payment_logs_where_params(username_filter, created_after, created_before_exclusive)
        params.extend([limit, offset])
        cursor.execute(
            f"""
                SELECT
                    l.id,
                    l.created_at,
                    l.event_type,
                    l.source,
                    l.username,
                    l.pedido_id,
                    l.id_externo,
                    l.meta,
                    u.porta AS cliente_porta,
                    u.limite_gb AS cliente_limite_gb,
                    u.status AS cliente_conta_status,
                    p.nome AS cliente_pais_nome,
                    COALESCE(
                        ped_id.status,
                        (SELECT px.status FROM painel_recarga_pedidos_pix px
                         WHERE px.id_externo = l.id_externo AND l.id_externo IS NOT NULL AND l.id_externo <> ''
                         ORDER BY px.id DESC LIMIT 1)
                    ) AS pedido_status,
                    COALESCE(
                        ped_id.valor_reais,
                        (SELECT px.valor_reais FROM painel_recarga_pedidos_pix px
                         WHERE px.id_externo = l.id_externo AND l.id_externo IS NOT NULL AND l.id_externo <> ''
                         ORDER BY px.id DESC LIMIT 1)
                    ) AS pedido_valor_reais,
                    COALESCE(
                        ped_id.gb_credito,
                        (SELECT px.gb_credito FROM painel_recarga_pedidos_pix px
                         WHERE px.id_externo = l.id_externo AND l.id_externo IS NOT NULL AND l.id_externo <> ''
                         ORDER BY px.id DESC LIMIT 1)
                    ) AS pedido_gb_credito,
                    COALESCE(
                        ped_id.username,
                        (SELECT px.username FROM painel_recarga_pedidos_pix px
                         WHERE px.id_externo = l.id_externo AND l.id_externo IS NOT NULL AND l.id_externo <> ''
                         ORDER BY px.id DESC LIMIT 1)
                    ) AS pedido_username
                FROM painel_recarga_payment_logs l
                LEFT JOIN usuarios_proxy u ON u.username = l.username
                LEFT JOIN painel_paises p ON p.id = u.pais_id
                LEFT JOIN painel_recarga_pedidos_pix ped_id ON ped_id.id = l.pedido_id
                {where_sql}
                ORDER BY l.id DESC
                LIMIT %s OFFSET %s
                """,
            tuple(params),
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_blocked_hosts_admin():
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, dominio, ativo, nota, created_at
            FROM painel_hosts_bloqueados
            ORDER BY id DESC
            """
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def list_blocked_domains_active_public() -> list[str]:
    """Domínios ativos para o proxy validar destinos (API pública)."""
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT dominio FROM painel_hosts_bloqueados
            WHERE ativo = 1
            ORDER BY dominio
            """
        )
        rows = cursor.fetchall()
        return [str(r[0]) for r in rows if r and r[0]]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def insert_blocked_host(dominio: str, nota: str | None) -> tuple[int | None, str | None]:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_hosts_bloqueados (dominio, ativo, nota)
            VALUES (%s, 1, %s)
            """,
            (dominio, nota),
        )
        conn.commit()
        return int(cursor.lastrowid) if cursor.lastrowid else None, None
    except Exception as e:
        conn.rollback()
        err = str(e).lower()
        if "duplicate" in err:
            return None, "Domínio já cadastrado"
        return None, "Não foi possível adicionar"
    finally:
        cursor.close()
        conn.close()


def delete_blocked_host(entry_id: int) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM painel_hosts_bloqueados WHERE id = %s", (int(entry_id),))
        ok = cursor.rowcount >= 1
        conn.commit()
        return ok
    except Exception:
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def desativar_logs_usuario(usuario: str) -> bool:
    conn = conexao_bd()
    cursor = conn.cursor()

    try:
        sql = """
            UPDATE logs_hosts_bloqueados
            SET status = 0
            WHERE username = %s
        """

        cursor.execute(sql, (usuario,))
        ok = cursor.rowcount >= 1

        conn.commit()
        return ok

    except Exception:
        conn.rollback()
        return False

    finally:
        cursor.close()
        conn.close()


def list_dashboard_proxy_hostnames() -> list[str]:
    """Hostnames ativos, ordenados, para o campo dashboard_proxy_hosts em /api/me."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT hostname FROM painel_dashboard_proxy_hosts
            WHERE ativo = 1
            ORDER BY sort_order ASC, id ASC
            """
        )
        rows = cursor.fetchall() or []
        out: list[str] = []
        for r in rows:
            h = (r.get("hostname") or "").strip().lower()
            if h:
                out.append(h)
        return out
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def replace_dashboard_proxy_hostnames(hosts: list[str]) -> tuple[bool, str | None]:
    """
    Substitui a lista inteira (ordem preservada, duplicatas ignoradas).
    hosts: já normalizados em minúsculas.
    """
    if len(hosts) > 80:
        return False, "No máximo 80 hosts"
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM painel_dashboard_proxy_hosts")
        for i, hostname in enumerate(hosts):
            cursor.execute(
                """
                INSERT INTO painel_dashboard_proxy_hosts (hostname, sort_order, ativo)
                VALUES (%s, %s, 1)
                """,
                (hostname, i),
            )
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


_SOCIO_PROXY_HOSTS_MAX_ACTIVE = 24


def list_approved_socio_proxy_hostnames(socio_username: str) -> list[str]:
    """Hosts aprovados para o sócio de topo, na ordem de criação (id)."""
    su = (socio_username or "").strip()
    if not su:
        return []
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT hostname FROM painel_socio_proxy_hosts
            WHERE socio_username = %s AND status = 'approved'
            ORDER BY id ASC
            """,
            (su,),
        )
        rows = cursor.fetchall() or []
        out: list[str] = []
        for r in rows:
            h = (r.get("hostname") or "").strip().lower()
            if h:
                out.append(h)
        return out
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def effective_dashboard_proxy_hostnames_for_user(user_row: dict | None) -> list[str]:
    """
    Lista exibida em /api/me (dashboard): se o «dono da marca» do usuário tiver ao menos um host
    aprovado em painel_socio_proxy_hosts, devolve só esses; senão, lista global do painel.
    """
    owner = socio_username_dono_branding(user_row)
    if owner:
        approved = list_approved_socio_proxy_hostnames(owner)
        if approved:
            return approved
    return list_dashboard_proxy_hostnames()


def list_socio_proxy_host_rows(socio_username: str) -> list[dict]:
    su = (socio_username or "").strip()
    if not su:
        return []
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
            FROM painel_socio_proxy_hosts
            WHERE socio_username = %s
            ORDER BY id DESC
            """,
            (su,),
        )
        rows = cursor.fetchall() or []
        return [_normalize_user_row(dict(r)) for r in rows]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def count_socio_proxy_hosts_active_slots(socio_username: str) -> int:
    """Quantidade de linhas pending ou approved (limite de slots por sócio)."""
    su = (socio_username or "").strip()
    if not su:
        return 0
    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*) FROM painel_socio_proxy_hosts
            WHERE socio_username = %s AND status IN ('pending', 'approved')
            """,
            (su,),
        )
        row = cursor.fetchone()
        if not row:
            return 0
        return int(row[0] or 0)
    except Exception:
        return 0
    finally:
        cursor.close()
        conn.close()


def propose_socio_proxy_host(socio_username: str, hostname: str) -> tuple[bool, str | None, dict | None]:
    """
    Insere pending, reabre pending se estava rejected, ou retorna erro se pending/approved.
    hostname já normalizado (minúsculas).
    """
    su = (socio_username or "").strip()
    hn = (hostname or "").strip().lower()
    if not su or not hn:
        return False, "Sócio ou host inválido", None
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, status FROM painel_socio_proxy_hosts
            WHERE socio_username = %s AND hostname = %s
            LIMIT 1
            """,
            (su, hn),
        )
        ex = cursor.fetchone()
        if ex:
            st = str(ex.get("status") or "").strip().lower()
            if st == "approved":
                return False, "Este host já está aprovado.", None
            if st == "pending":
                return False, "Este host já está aguardando análise do administrador.", None
            if st == "rejected":
                cursor.execute(
                    """
                    UPDATE painel_socio_proxy_hosts
                    SET status = 'pending', reviewed_at = NULL, reviewed_by = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (int(ex["id"]),),
                )
                conn.commit()
                cursor.execute(
                    """
                    SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
                    FROM painel_socio_proxy_hosts WHERE id = %s
                    """,
                    (int(ex["id"]),),
                )
                row = cursor.fetchone()
                return True, None, _normalize_user_row(dict(row)) if row else None

        if count_socio_proxy_hosts_active_slots(su) >= _SOCIO_PROXY_HOSTS_MAX_ACTIVE:
            return (
                False,
                f"No máximo {_SOCIO_PROXY_HOSTS_MAX_ACTIVE} hosts em análise ou aprovados por sócio. Remova ou aguarde análise.",
                None,
            )

        cursor.execute(
            """
            INSERT INTO painel_socio_proxy_hosts (socio_username, hostname, status)
            VALUES (%s, %s, 'pending')
            """,
            (su, hn),
        )
        new_id = cursor.lastrowid
        conn.commit()
        cursor.execute(
            """
            SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
            FROM painel_socio_proxy_hosts WHERE id = %s
            """,
            (int(new_id),),
        )
        row = cursor.fetchone()
        return True, None, _normalize_user_row(dict(row)) if row else None
    except Exception as e:
        conn.rollback()
        return False, str(e), None
    finally:
        cursor.close()
        conn.close()


def list_socio_proxy_hosts_for_dono(
    status: str | None = None,
    socio_username: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Listagem para o dono (ARE CEO): todos os sócios ou filtrado."""
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    lim = max(1, min(int(limit), 2000))
    try:
        where: list[str] = []
        params: list = []
        if status and str(status).strip().lower() in ("pending", "approved", "rejected"):
            where.append("status = %s")
            params.append(str(status).strip().lower())
        if socio_username and str(socio_username).strip():
            where.append("socio_username = %s")
            params.append(str(socio_username).strip())
        wh = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(lim)
        cursor.execute(
            f"""
            SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
            FROM painel_socio_proxy_hosts
            {wh}
            ORDER BY
              CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
              created_at DESC
            LIMIT %s
            """,
            tuple(params),
        )
        rows = cursor.fetchall() or []
        return [_normalize_user_row(dict(r)) for r in rows]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()


def get_socio_proxy_host_by_id(entry_id: int) -> dict | None:
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
            FROM painel_socio_proxy_hosts WHERE id = %s LIMIT 1
            """,
            (int(entry_id),),
        )
        row = cursor.fetchone()
        return _normalize_user_row(dict(row)) if row else None
    except Exception:
        return None
    finally:
        cursor.close()
        conn.close()


def dono_set_socio_proxy_host_status(
    entry_id: int,
    new_status: str,
    reviewer_username: str,
) -> tuple[bool, str | None, dict | None]:
    if new_status not in ("approved", "rejected"):
        return False, "status deve ser approved ou rejected", None
    row = get_socio_proxy_host_by_id(entry_id)
    if not row:
        return False, "Registro não encontrado", None
    cur = str(row.get("status") or "").strip().lower()
    if cur == new_status:
        return True, None, row
    rev = (reviewer_username or "").strip()[:191]
    conn = conexao_bd()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            UPDATE painel_socio_proxy_hosts
            SET status = %s,
                reviewed_at = CURRENT_TIMESTAMP,
                reviewed_by = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (new_status, rev or None, int(entry_id)),
        )
        conn.commit()
        cursor.execute(
            """
            SELECT id, socio_username, hostname, status, created_at, updated_at, reviewed_at, reviewed_by
            FROM painel_socio_proxy_hosts WHERE id = %s
            """,
            (int(entry_id),),
        )
        fresh = cursor.fetchone()
        return True, None, _normalize_user_row(dict(fresh)) if fresh else None
    except Exception as e:
        conn.rollback()
        return False, str(e), None
    finally:
        cursor.close()
        conn.close()


def upsert_usuario_threads(username: str, threads: int) -> tuple[bool, str | None]:
    """Grava painel_usuario_threads. threads entre 1 e 10_000_000."""
    un = (username or "").strip()[:128]
    if not un:
        return False, "username inválido"
    try:
        tv = int(threads)
    except (TypeError, ValueError):
        return False, "threads inválido"
    if tv < 1 or tv > 10_000_000:
        return False, "Informe threads entre 1 e 10.000.000"

    conn = conexao_bd()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO painel_usuario_threads (username, threads)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE threads = VALUES(threads)
            """,
            (un, tv),
        )
        conn.commit()
        return True, None
    except Exception as e:
        conn.rollback()
        return False, str(e)[:500]
    finally:
        cursor.close()
        conn.close()