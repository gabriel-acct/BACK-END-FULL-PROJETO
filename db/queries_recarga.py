"""Queries de recarga PIX (PushinPay)."""

from __future__ import annotations

import json
from decimal import ROUND_HALF_UP, Decimal

import mysql.connector

from db._db_helpers import fechar_conexao
from db.conexao import conexao


def get_recarga_por_gb_config() -> dict:
    defaults = {
        "preco_por_gb_reais": 9.90,
        "gb_min": 1.0,
        "gb_max": 500.0,
        "gb_step": 1.0,
        "max_total_reais": 50000.0,
    }
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return defaults
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT preco_por_gb_reais, gb_min, gb_max, gb_step, max_total_reais
            FROM painel_recarga_config
            WHERE id = 1
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if not row:
            return defaults
        out = {
            "preco_por_gb_reais": float(row["preco_por_gb_reais"]),
            "gb_min": float(row["gb_min"]),
            "gb_max": float(row["gb_max"]),
            "gb_step": float(row["gb_step"] or 1),
            "max_total_reais": float(row.get("max_total_reais") or defaults["max_total_reais"]),
        }
        return out
    except mysql.connector.Error:
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
                "max_total_reais": defaults["max_total_reais"],
            }
        except Exception:
            return defaults
    except Exception:
        return defaults
    finally:
        fechar_conexao(conn, cursor)


def update_recarga_config_fields(fields: dict) -> tuple[bool, str | None]:
    allowed = {"preco_por_gb_reais", "gb_min", "gb_max", "gb_step", "max_total_reais"}
    parts: list[str] = []
    params: list = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        parts.append(f"{k} = %s")
        params.append(float(v))
    if not parts:
        return True, None
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False, "Sem conexão com o banco"
        cursor = conn.cursor()
        sql = f"UPDATE painel_recarga_config SET {', '.join(parts)} WHERE id = 1"
        cursor.execute(sql, tuple(params))
        conn.commit()
        return True, None
    except Exception as e:
        if conn:
            conn.rollback()
        return False, str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def list_recarga_descontos_para_calculo():
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
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
        fechar_conexao(conn, cursor)


def list_recarga_descontos_admin():
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
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
        fechar_conexao(conn, cursor)


def get_recarga_desconto_by_id(did: int):
    conn = None
    cursor = None
    try:
        conn = conexao()
        cursor = conn.cursor(dictionary=True)
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
        fechar_conexao(conn, cursor)


def create_recarga_desconto(
    nome: str,
    gb_minimo: float,
    percentual_desconto: float | None,
    valor_fixo_reais: float | None,
    ativo: int,
    ordem: int,
) -> int | None:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return None
        cursor = conn.cursor()
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
        if conn:
            conn.rollback()
        return None
    finally:
        fechar_conexao(conn, cursor)


def update_recarga_desconto_fields(did: int, fields: dict) -> bool:
    allowed = {"nome", "gb_minimo", "percentual_desconto", "valor_fixo_reais", "ativo", "ordem"}
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False
        cursor = conn.cursor()
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
        cursor.execute(f"UPDATE painel_recarga_descontos SET {', '.join(parts)} WHERE id = %s", vals)
        conn.commit()
        return cursor.rowcount >= 1
    except Exception:
        if conn:
            conn.rollback()
        return False
    finally:
        fechar_conexao(conn, cursor)


def delete_recarga_desconto(did: int) -> bool:
    conn = None
    cursor = None
    try:
        conn = conexao()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM painel_recarga_descontos WHERE id = %s", (int(did),))
        conn.commit()
        return cursor.rowcount >= 1
    except Exception:
        if conn:
            conn.rollback()
        return False
    finally:
        fechar_conexao(conn, cursor)


def get_pushinpay_config_row() -> dict | None:
    conn = None
    cursor = None
    sql_full = """
            SELECT id, api_base, api_token, site_public_url, webhook_secret, webhook_header,
                   webhook_require_secret, webhook_force_secret,
                   recarga_pix_max_per_hour, recarga_pix_sync_max_per_hour, atualizado_em
            FROM painel_pushinpay_config
            WHERE id = 1
            LIMIT 1
            """
    sql_legacy = """
            SELECT id, api_base, api_token, site_public_url, webhook_secret, webhook_header,
                   webhook_require_secret, recarga_pix_max_per_hour, atualizado_em
            FROM painel_pushinpay_config
            WHERE id = 1
            LIMIT 1
            """
    try:
        conn = conexao()
        if not conn:
            return None
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(sql_full)
        except mysql.connector.Error:
            cursor.execute(sql_legacy)
        row = cursor.fetchone()
        if row:
            row.setdefault("webhook_force_secret", 1)
            row.setdefault("recarga_pix_sync_max_per_hour", 60)
        return row
    except Exception:
        return None
    finally:
        fechar_conexao(conn, cursor)


def update_pushinpay_config_fields(fields: dict) -> tuple[bool, str | None]:
    allowed = {
        "api_base",
        "api_token",
        "site_public_url",
        "webhook_secret",
        "webhook_header",
        "webhook_require_secret",
        "webhook_force_secret",
        "recarga_pix_max_per_hour",
        "recarga_pix_sync_max_per_hour",
    }
    parts: list[str] = []
    params: list = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k in ("webhook_require_secret", "webhook_force_secret"):
            parts.append(f"{k} = %s")
            params.append(1 if v else 0)
        elif k in ("recarga_pix_max_per_hour", "recarga_pix_sync_max_per_hour"):
            parts.append(f"{k} = %s")
            params.append(int(v))
        else:
            parts.append(f"{k} = %s")
            params.append(v)
    if not parts:
        return True, None
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False, "Sem conexão"
        cursor = conn.cursor()
        cursor.execute(f"UPDATE painel_pushinpay_config SET {', '.join(parts)} WHERE id = 1", tuple(params))
        conn.commit()
        return True, None
    except Exception as e:
        if conn:
            conn.rollback()
        return False, str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def _mysql_pedido_pix_err_msg(exc: mysql.connector.Error) -> str:
    code = getattr(exc, "errno", None)
    raw = (getattr(exc, "msg", None) or str(exc)).strip()
    if code == 1146:
        return "Tabela painel_recarga_pedidos_pix não existe. Execute sql/002_recarga_pushinpay.sql."
    if code == 1406:
        return "Campo payload_pix muito curto — use MEDIUMTEXT (ver sql/002_recarga_pushinpay.sql)."
    if code == 1062:
        return f"ID externo duplicado: {raw}"
    return raw[:400] if raw else "Erro ao gravar pedido"


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
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return None, "Sem conexão com o banco"
        cursor = conn.cursor()
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
                str(payload_pix),
                src,
                socio_b,
            ),
        )
        conn.commit()
        lid = cursor.lastrowid
        return (int(lid), None) if lid else (None, "Falha ao obter id do pedido")
    except mysql.connector.Error as e:
        if conn:
            conn.rollback()
        return None, _mysql_pedido_pix_err_msg(e)
    except Exception as e:
        if conn:
            conn.rollback()
        return None, str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def list_recarga_pedidos_pix_for_user(username: str, limit: int = 30):
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
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
        fechar_conexao(conn, cursor)


def get_pedido_pix_by_id_externo(id_externo: str) -> dict | None:
    id_externo = (id_externo or "").strip()[:80]
    if not id_externo:
        return None
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return None
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, username, gb_credito, valor_reais, status
            FROM painel_recarga_pedidos_pix
            WHERE id_externo = %s
            LIMIT 1
            """,
            (id_externo,),
        )
        return cursor.fetchone()
    except Exception:
        return None
    finally:
        fechar_conexao(conn, cursor)


def count_pix_pedidos_recent_for_user(username: str, hours: float = 1.0) -> int:
    """Cobranças PIX criadas na última hora (rate limit persistente)."""
    username = (username or "").strip()[:128]
    if not username:
        return 0
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return 0
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT COUNT(*) AS c
            FROM painel_recarga_pedidos_pix
            WHERE username = %s
              AND criado_em >= (NOW() - INTERVAL %s SECOND)
            """,
            (username, max(60, int(hours * 3600))),
        )
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        fechar_conexao(conn, cursor)


def get_pedido_pix_by_id_for_user(pedido_id: int, username: str):
    conn = None
    cursor = None
    try:
        conn = conexao()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, username, preco_id, gb_credito, valor_reais, status, id_externo, payload_pix,
                   pushinpay_source, socio_billing_username, criado_em, atualizado_em
            FROM painel_recarga_pedidos_pix
            WHERE id = %s AND username = %s
            LIMIT 1
            """,
            (int(pedido_id), username[:128]),
        )
        return cursor.fetchone()
    finally:
        fechar_conexao(conn, cursor)


def _decimal_centavos_from_reais(valor_reais) -> int:
    d = Decimal(str(valor_reais))
    return int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def finalize_pix_pedido_from_gateway(
    id_externo: str,
    remote_status: str,
    value_cents_remote: int | None,
) -> str:
    """Credita GB na API DataImpulse quando status = paid."""
    id_externo = (id_externo or "").strip()
    if not id_externo:
        return "not_found"

    st = (remote_status or "").lower().strip()
    if st == "cancelled":
        st = "canceled"

    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return "error"
        cursor = conn.cursor(dictionary=True)
        cursor.execute("START TRANSACTION")
        cursor.execute(
            """
            SELECT id, username, gb_credito, valor_reais, status
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
                insert_recarga_payment_log(
                    "pix_valor_divergente",
                    "system",
                    username=str(row["username"]),
                    pedido_id=int(row["id"]),
                    id_externo=id_externo,
                    severity="error",
                    meta={
                        "esperado_centavos": expected_cents,
                        "recebido_centavos": value_cents_remote,
                    },
                )
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

            try:
                subuser_id = int(str(row["username"]).strip())
            except (TypeError, ValueError):
                conn.rollback()
                return "error"

            from app.service.sub_usuarios import add_subuser_balance

            credit = add_subuser_balance(subuser_id, delta_gb)
            if not credit.get("status"):
                conn.rollback()
                insert_recarga_payment_log(
                    "pix_credito_api_falhou",
                    "system",
                    username=str(row["username"]),
                    pedido_id=int(row["id"]),
                    id_externo=id_externo,
                    severity="error",
                    meta={
                        "subuser_id": subuser_id,
                        "gb": delta_gb,
                        "api_message": str(credit.get("message", ""))[:500],
                    },
                )
                return "credit_failed"

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
        if conn:
            conn.rollback()
        return "error"
    finally:
        fechar_conexao(conn, cursor)


def _pedidos_where_params(
    status_filter: str | None = None,
    username_filter: str | None = None,
) -> tuple[str, list]:
    wheres: list[str] = []
    params: list = []
    st = (status_filter or "").strip().lower()
    if st:
        wheres.append("status = %s")
        params.append(st[:32])
    uf = (username_filter or "").strip()
    if uf:
        wheres.append("username LIKE %s")
        params.append(f"%{uf[:128]}%")
    where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
    return where_sql, params


def count_recarga_pedidos_pix_admin(
    status_filter: str | None = None,
    username_filter: str | None = None,
) -> int:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return 0
        cursor = conn.cursor(dictionary=True)
        where_sql, params = _pedidos_where_params(status_filter, username_filter)
        cursor.execute(f"SELECT COUNT(*) AS c FROM painel_recarga_pedidos_pix {where_sql}", tuple(params))
        row = cursor.fetchone()
        return int(row["c"]) if row else 0
    except Exception:
        return 0
    finally:
        fechar_conexao(conn, cursor)


def list_recarga_pedidos_pix_admin(
    limit: int = 50,
    offset: int = 0,
    status_filter: str | None = None,
    username_filter: str | None = None,
):
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        where_sql, params = _pedidos_where_params(status_filter, username_filter)
        params.extend([limit, offset])
        cursor.execute(
            f"""
            SELECT id, username, preco_id, gb_credito, valor_reais, status, id_externo,
                   pushinpay_source, socio_billing_username, criado_em, atualizado_em
            FROM painel_recarga_pedidos_pix
            {where_sql}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params),
        )
        return cursor.fetchall()
    except Exception:
        return []
    finally:
        fechar_conexao(conn, cursor)


def recarga_pedidos_stats() -> dict:
    """Contagens por status para o dashboard admin."""
    conn = None
    cursor = None
    defaults = {"total": 0, "pending": 0, "paid": 0, "canceled": 0, "expired": 0}
    try:
        conn = conexao()
        if not conn:
            return defaults
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT status, COUNT(*) AS c
            FROM painel_recarga_pedidos_pix
            GROUP BY status
            """
        )
        rows = cursor.fetchall()
        out = dict(defaults)
        for r in rows:
            st = (r.get("status") or "").lower()
            c = int(r.get("c") or 0)
            out["total"] += c
            if st in out:
                out[st] = c
        return out
    except Exception:
        return defaults
    finally:
        fechar_conexao(conn, cursor)


def _table_exists(cursor, table_name: str) -> bool:
    try:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = %s
            LIMIT 1
            """,
            (table_name,),
        )
        return cursor.fetchone() is not None
    except Exception:
        return False


def payment_logs_db_status() -> dict:
    """Diagnóstico das tabelas de log (recarga + legado)."""
    conn = None
    cursor = None
    out = {
        "recarga_table": False,
        "legacy_table": False,
        "recarga_count": 0,
        "legacy_count": 0,
        "pedidos_pix_count": 0,
        "error": None,
    }
    try:
        conn = conexao()
        if not conn:
            out["error"] = "Sem conexão com o banco"
            return out
        cursor = conn.cursor(dictionary=True)
        out["recarga_table"] = _table_exists(cursor, "painel_recarga_payment_logs")
        out["legacy_table"] = _table_exists(cursor, "painel_payment_logs")
        if out["recarga_table"]:
            cursor.execute("SELECT COUNT(*) AS c FROM painel_recarga_payment_logs")
            row = cursor.fetchone()
            out["recarga_count"] = int(row["c"]) if row else 0
        if out["legacy_table"]:
            cursor.execute("SELECT COUNT(*) AS c FROM painel_payment_logs")
            row = cursor.fetchone()
            out["legacy_count"] = int(row["c"]) if row else 0
        if _table_exists(cursor, "painel_recarga_pedidos_pix"):
            cursor.execute("SELECT COUNT(*) AS c FROM painel_recarga_pedidos_pix")
            row = cursor.fetchone()
            out["pedidos_pix_count"] = int(row["c"]) if row else 0
        return out
    except Exception as e:
        out["error"] = str(e)[:400]
        return out
    finally:
        fechar_conexao(conn, cursor)


def _payment_logs_union_subqueries(cursor) -> tuple[list[str], list[str]]:
    """Partes do UNION ALL para listagem unificada."""
    parts: list[str] = []
    errors: list[str] = []
    if _table_exists(cursor, "painel_recarga_payment_logs"):
        parts.append(
            """
            SELECT
              CONCAT('r-', l.id) AS row_key,
              l.id AS id,
              'recarga' AS log_origin,
              l.created_at,
              l.event_type,
              l.source,
              COALESCE(l.severity, 'info') AS severity,
              l.username,
              l.pedido_id,
              l.id_externo,
              l.client_ip,
              l.user_agent,
              l.request_id,
              l.meta,
              p.status AS pedido_status,
              p.valor_reais AS pedido_valor_reais,
              p.gb_credito AS pedido_gb_credito
            FROM painel_recarga_payment_logs l
            LEFT JOIN painel_recarga_pedidos_pix p ON p.id = l.pedido_id
            """
        )
    else:
        errors.append("Tabela painel_recarga_payment_logs ausente (execute sql/002_recarga_pushinpay.sql)")

    if _table_exists(cursor, "painel_payment_logs"):
        parts.append(
            """
            SELECT
              CONCAT('l-', pl.id) AS row_key,
              pl.id AS id,
              'legacy' AS log_origin,
              pl.created_at,
              pl.event_type,
              pl.source,
              'info' AS severity,
              pl.username,
              NULL AS pedido_id,
              pl.external_id AS id_externo,
              NULL AS client_ip,
              NULL AS user_agent,
              NULL AS request_id,
              CAST(pl.meta AS CHAR) AS meta,
              NULL AS pedido_status,
              NULL AS pedido_valor_reais,
              NULL AS pedido_gb_credito
            FROM painel_payment_logs pl
            """
        )
    return parts, errors


def _payment_logs_outer_where(username_filter: str | None) -> tuple[str, list]:
    uf = (username_filter or "").strip()
    if not uf:
        return "", []
    like = f"%{uf}%"
    return (
        "WHERE (username LIKE %s OR id_externo LIKE %s OR CAST(pedido_id AS CHAR) LIKE %s OR event_type LIKE %s)",
        [like, like, like, like],
    )


def count_recarga_payment_logs_all(username_filter: str | None = None) -> int:
    ok, total, _ = count_payment_logs_unified(username_filter)
    return total if ok else 0


def count_payment_logs_unified(username_filter: str | None = None) -> tuple[bool, int, str | None]:
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False, 0, "Sem conexão com o banco"
        cursor = conn.cursor(dictionary=True)
        parts, errors = _payment_logs_union_subqueries(cursor)
        if not parts:
            return False, 0, "; ".join(errors) or "Nenhuma tabela de logs encontrada"
        union_sql = " UNION ALL ".join(parts)
        where_sql, params = _payment_logs_outer_where(username_filter)
        sql = f"SELECT COUNT(*) AS c FROM ({union_sql}) AS logs {where_sql}"
        cursor.execute(sql, tuple(params))
        row = cursor.fetchone()
        return True, int(row["c"]) if row else 0, None
    except Exception as e:
        return False, 0, str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def list_recarga_payment_logs_all(
    limit: int = 50,
    offset: int = 0,
    username_filter: str | None = None,
):
    ok, rows, _ = list_payment_logs_unified(limit, offset, username_filter)
    return rows if ok else []


def list_payment_logs_unified(
    limit: int = 50,
    offset: int = 0,
    username_filter: str | None = None,
) -> tuple[bool, list, str | None]:
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            return False, [], "Sem conexão com o banco"
        cursor = conn.cursor(dictionary=True)
        parts, errors = _payment_logs_union_subqueries(cursor)
        if not parts:
            return False, [], "; ".join(errors) or "Nenhuma tabela de logs encontrada"
        union_sql = " UNION ALL ".join(parts)
        where_sql, params = _payment_logs_outer_where(username_filter)
        params.extend([limit, offset])
        sql = f"""
            SELECT row_key, id, log_origin, created_at, event_type, source, severity,
                   username, pedido_id, id_externo, client_ip, user_agent, request_id, meta,
                   pedido_status, pedido_valor_reais, pedido_gb_credito
            FROM ({union_sql}) AS logs
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT %s OFFSET %s
            """
        cursor.execute(sql, tuple(params))
        return True, cursor.fetchall(), None
    except mysql.connector.Error as e:
        return False, [], str(e)[:400]
    except Exception as e:
        return False, [], str(e)[:400]
    finally:
        fechar_conexao(conn, cursor)


def backfill_recarga_payment_logs_from_pedidos() -> dict:
    """Gera logs a partir dos pedidos PIX já existentes (idempotente)."""
    conn = None
    cursor = None
    result = {"status": False, "inserted": 0, "skipped": 0, "message": ""}
    try:
        conn = conexao()
        if not conn:
            result["message"] = "Sem conexão com o banco"
            return result
        cursor = conn.cursor(dictionary=True)
        if not _table_exists(cursor, "painel_recarga_payment_logs"):
            result["message"] = "Tabela painel_recarga_payment_logs não existe"
            return result
        if not _table_exists(cursor, "painel_recarga_pedidos_pix"):
            result["message"] = "Tabela painel_recarga_pedidos_pix não existe"
            return result
        cursor.execute(
            """
            SELECT id, username, gb_credito, valor_reais, status, id_externo, criado_em
            FROM painel_recarga_pedidos_pix
            ORDER BY id ASC
            """
        )
        pedidos = cursor.fetchall() or []
        inserted = 0
        skipped = 0

        for row in pedidos:
            pid = int(row["id"])
            cursor.execute(
                """
                SELECT id FROM painel_recarga_payment_logs
                WHERE pedido_id = %s AND event_type = 'pix_pedido_registrado'
                LIMIT 1
                """,
                (pid,),
            )
            if cursor.fetchone():
                skipped += 1
            else:
                insert_recarga_payment_log(
                    "pix_pedido_registrado",
                    "backfill",
                    username=str(row.get("username") or ""),
                    pedido_id=pid,
                    id_externo=str(row.get("id_externo") or ""),
                    meta={
                        "status": row.get("status"),
                        "gb_credito": float(row.get("gb_credito") or 0),
                        "valor_reais": float(row.get("valor_reais") or 0),
                        "criado_em": str(row.get("criado_em") or ""),
                        "backfill": True,
                    },
                )
                inserted += 1

            st = (str(row.get("status") or "")).lower()
            if st == "paid":
                cursor.execute(
                    """
                    SELECT id FROM painel_recarga_payment_logs
                    WHERE pedido_id = %s AND event_type = 'pix_pedido_pago'
                    LIMIT 1
                    """,
                    (pid,),
                )
                if not cursor.fetchone():
                    insert_recarga_payment_log(
                        "pix_pedido_pago",
                        "backfill",
                        username=str(row.get("username") or ""),
                        pedido_id=pid,
                        id_externo=str(row.get("id_externo") or ""),
                        severity="info",
                        meta={"status": "paid", "backfill": True},
                    )
                    inserted += 1
                else:
                    skipped += 1

        result["status"] = True
        result["inserted"] = inserted
        result["skipped"] = skipped
        result["message"] = f"{inserted} log(s) criado(s), {skipped} já existiam"
        return result
    except Exception as e:
        result["message"] = str(e)[:400]
        return result
    finally:
        fechar_conexao(conn, cursor)


def insert_recarga_payment_log(
    event_type: str,
    source: str,
    *,
    username: str | None = None,
    pedido_id: int | None = None,
    id_externo: str | None = None,
    meta: dict | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    severity: str = "info",
) -> None:
    import logging

    log = logging.getLogger(__name__)

    meta_s = None
    if meta is not None:
        meta_s = json.dumps(meta, ensure_ascii=False, default=str)
        if len(meta_s) > 60000:
            meta_s = meta_s[:60000] + "…"
    sev = (severity or "info").strip().lower()[:16]
    if sev not in ("info", "warn", "error"):
        sev = "info"

    conn = None
    cursor = None
    try:
        conn = conexao()
        if not conn:
            log.error("payment_log: sem conexão DB (%s)", event_type[:40])
            return
        cursor = conn.cursor()
        params_full = (
            event_type[:80],
            source[:32],
            (username or "").strip()[:128] or None,
            pedido_id,
            (id_externo or "").strip()[:80] or None,
            (client_ip or "").strip()[:45] or None,
            (user_agent or "").strip()[:255] or None,
            (request_id or "").strip()[:64] or None,
            sev,
            meta_s,
        )
        try:
            cursor.execute(
                """
                INSERT INTO painel_recarga_payment_logs
                  (event_type, source, username, pedido_id, id_externo,
                   client_ip, user_agent, request_id, severity, meta)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                params_full,
            )
        except mysql.connector.Error:
            cursor.execute(
                """
                INSERT INTO painel_recarga_payment_logs
                  (event_type, source, username, pedido_id, id_externo, meta)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    event_type[:80],
                    source[:32],
                    (username or "").strip()[:128] or None,
                    pedido_id,
                    (id_externo or "").strip()[:80] or None,
                    meta_s,
                ),
            )
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        log.exception("payment_log insert failed: %s — %s", event_type, e)
    finally:
        fechar_conexao(conn, cursor)
