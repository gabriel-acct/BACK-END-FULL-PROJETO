"""Auditoria centralizada de eventos PIX / PushinPay."""
from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Any

from flask import has_request_context, request

from db import queries_recarga as queries

_webhook_ip_bucket: dict[str, list[float]] = defaultdict(list)
_sync_ip_bucket: dict[str, list[float]] = defaultdict(list)


def client_ip() -> str | None:
    if not has_request_context():
        return None
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()[:45] or None
    ra = request.remote_addr
    return str(ra)[:45] if ra else None


def user_agent() -> str | None:
    if not has_request_context():
        return None
    ua = (request.headers.get("User-Agent") or "").strip()
    return ua[:255] if ua else None


def request_id() -> str:
    if has_request_context():
        rid = getattr(request, "_payment_request_id", None)
        if not rid:
            rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
            request._payment_request_id = rid  # type: ignore[attr-defined]
        return str(rid)[:64]
    return str(uuid.uuid4())[:64]


def subuser_context(user: dict | None, token_payload: dict | None = None) -> dict[str, Any]:
    """Metadados do sub-usuário (sem senha)."""
    if not user:
        return {}
    u = user.get("user") if isinstance(user.get("user"), dict) else {}
    out: dict[str, Any] = {}
    if u.get("id") is not None:
        out["subuser_id"] = u.get("id")
    for key in ("label", "login", "email", "username", "name", "threads", "balance"):
        if u.get(key) is not None:
            out[key] = u.get(key)
    if token_payload:
        if token_payload.get("sub") is not None:
            out["jwt_sub"] = token_payload.get("sub")
        if token_payload.get("exp") is not None:
            out["jwt_exp"] = token_payload.get("exp")
    return out


def _merge_meta(base: dict | None, extra: dict | None) -> dict:
    m: dict[str, Any] = {}
    if base:
        m.update(base)
    if extra:
        m.update(extra)
    ctx = {"ip": client_ip(), "ua": user_agent(), "request_id": request_id()}
    for k, v in ctx.items():
        if v and k not in m:
            m[k] = v
    return m


def log_payment_event(
    event_type: str,
    source: str,
    *,
    severity: str = "info",
    username: str | None = None,
    pedido_id: int | None = None,
    id_externo: str | None = None,
    meta: dict | None = None,
    user: dict | None = None,
    token_payload: dict | None = None,
) -> None:
    """Grava em painel_recarga_payment_logs com contexto HTTP e usuário."""
    merged = _merge_meta(meta, subuser_context(user, token_payload))
    queries.insert_recarga_payment_log(
        event_type,
        source,
        username=username,
        pedido_id=pedido_id,
        id_externo=id_externo,
        meta=merged,
        client_ip=client_ip(),
        user_agent=user_agent(),
        request_id=request_id(),
        severity=severity,
    )


def lookup_pedido_refs(id_externo: str | None) -> tuple[int | None, str | None]:
    if not id_externo:
        return None, None
    row = queries.get_pedido_pix_by_id_externo(id_externo)
    if not row:
        return None, None
    return int(row["id"]), str(row.get("username") or "") or None


def finalize_pix_and_log(
    id_externo: str,
    remote_status: str,
    value_cents_remote: int | None,
    *,
    source: str,
    log_prefix: str = "pix",
    user: dict | None = None,
    token_payload: dict | None = None,
    pedido_id_hint: int | None = None,
    username_hint: str | None = None,
) -> str:
    """Finaliza pedido e registra resultado com contexto completo."""
    pid, uname = lookup_pedido_refs(id_externo)
    pedido_id = pedido_id_hint or pid
    username = username_hint or uname

    result = queries.finalize_pix_pedido_from_gateway(id_externo, remote_status, value_cents_remote)

    sev = "info"
    if result in ("credit_failed", "value_mismatch", "error"):
        sev = "error"
    elif result in ("missing_value", "invalid_transition", "not_found"):
        sev = "warn"

    log_payment_event(
        f"{log_prefix}_finalizacao",
        source,
        severity=sev,
        username=username,
        pedido_id=pedido_id,
        id_externo=id_externo,
        meta={
            "resultado": result,
            "status_remoto": str(remote_status or "")[:120],
            "value_cents": value_cents_remote,
        },
        user=user,
        token_payload=token_payload,
    )
    return result


def allow_webhook_ip(max_per_minute: int = 120) -> bool:
    ip = client_ip() or "unknown"
    now = time.time()
    window = 60.0
    bucket = _webhook_ip_bucket[ip]
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= max_per_minute:
        return False
    bucket.append(now)
    return True


def allow_sync_frequency(subuser_key: str, max_per_hour: int = 60) -> bool:
    """Limite de sincronizações manuais por sub-usuário (memória + já coberto por DB na cobrança)."""
    now = time.time()
    window = 3600.0
    key = f"sync:{subuser_key}"
    bucket = _sync_ip_bucket[key]
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= max_per_hour:
        return False
    bucket.append(now)
    return True


def webhook_must_reject_unconfigured() -> bool:
    """Lê painel_pushinpay_config.webhook_force_secret (MySQL)."""
    from app.service.pushinpay_credentials import merged_pushinpay_global

    return bool(merged_pushinpay_global().get("webhook_force_secret"))
