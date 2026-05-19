"""Resolve PushinPay (PIX): config global no banco + env, e conta do sócio para filhos (`criado_por`)."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from flask import current_app

from cpa_panel.db import queries
from cpa_panel.db.queries import _criado_por_str, get_socio_pushinpay, usuario_e_socio_responsavel

_DEFAULT_API = "https://api.pushinpay.com.br/api"


def _strip_or_none(s: str | None) -> str | None:
    if s is None:
        return None
    t = str(s).strip()
    return t if t else None


def _api_base_safe(raw: str | None) -> str:
    base = (raw or _DEFAULT_API).strip().rstrip("/")
    if "pushinpay.com.br" not in base.lower():
        return _DEFAULT_API
    return base


def merged_pushinpay_global() -> dict:
    """Campos efetivos: DB `painel_pushinpay_config` sobrescreve env quando preenchidos."""
    row = queries.get_pushinpay_config_row()
    cfg = current_app.config
    db_token = _strip_or_none(row.get("api_token")) if row else None
    db_base = _strip_or_none(row.get("api_base")) if row else None
    db_site = _strip_or_none(row.get("site_public_url")) if row else None
    db_wh_secret = _strip_or_none(row.get("webhook_secret")) if row else None
    db_wh_header = _strip_or_none(row.get("webhook_header")) if row else None
    db_req = None
    if row and row.get("webhook_require_secret") is not None:
        db_req = int(row["webhook_require_secret"] or 0) == 1
    db_max_h = None
    if row and row.get("recarga_pix_max_per_hour") is not None:
        try:
            db_max_h = int(row["recarga_pix_max_per_hour"])
        except (TypeError, ValueError):
            db_max_h = None

    token = (db_token or (cfg.get("PUSHINPAY_API_TOKEN") or "")).strip()
    api_base = _api_base_safe(db_base or (cfg.get("PUSHINPAY_API_BASE") or _DEFAULT_API))
    site = (db_site or (cfg.get("SITE_PUBLIC_URL") or "")).strip().rstrip("/")
    wh_secret = (db_wh_secret or (cfg.get("PUSHINPAY_WEBHOOK_SECRET") or "")).strip()
    wh_header = (db_wh_header or (cfg.get("PUSHINPAY_WEBHOOK_HEADER") or "X-Webhook-Token")).strip()
    if db_req is None:
        require = bool(cfg.get("PUSHINPAY_WEBHOOK_REQUIRE_SECRET"))
    else:
        require = db_req
    max_h = db_max_h if db_max_h is not None and db_max_h > 0 else int(cfg.get("RECARGA_PIX_MAX_PER_HOUR") or 30)
    return {
        "api_token": token,
        "api_base": api_base,
        "site_public_url": site,
        "webhook_secret": wh_secret,
        "webhook_header": wh_header,
        "webhook_require_secret": require,
        "recarga_pix_max_per_hour": max_h,
    }


def effective_recarga_pix_max_per_hour() -> int:
    return int(merged_pushinpay_global().get("recarga_pix_max_per_hour") or 30)


def global_webhook_url() -> str | None:
    site = merged_pushinpay_global()["site_public_url"]
    if not site:
        return None
    return f"{site}/api/webhooks/cpa/pushinpay/pix"


def socio_webhook_url(socio_username: str) -> str | None:
    site = merged_pushinpay_global()["site_public_url"]
    if not site:
        return None
    su = (socio_username or "").strip()
    if not su:
        return None
    return f"{site}/api/webhooks/cpa/pushinpay/pix/socio/{quote(su, safe='')}"


@dataclass(frozen=True)
class ResolvedPushinPay:
    mode: str
    socio_billing_username: str | None
    api_token: str
    api_base: str
    webhook_callback_url: str | None


def _socio_resolved(socio_un: str, sp: dict) -> ResolvedPushinPay | None:
    tok = (sp.get("api_token") or "").strip()
    if not tok:
        return None
    g = merged_pushinpay_global()
    api_base = _api_base_safe(_strip_or_none(sp.get("api_base")) or g["api_base"])
    return ResolvedPushinPay(
        mode="socio",
        socio_billing_username=socio_un.strip()[:128],
        api_token=tok,
        api_base=api_base,
        webhook_callback_url=socio_webhook_url(socio_un),
    )


def resolve_pushinpay_for_proxy_user(user_row: dict | None) -> ResolvedPushinPay | None:
    """
    Filho (`criado_por`) usa a conta do sócio se estiver cadastrada.
    Sócio de topo com cadastro usa a própria conta nas recargas dele.
    Demais casos: conta global.
    """
    if not user_row:
        return None
    un = str(user_row.get("username") or "").strip()
    cp = _criado_por_str(user_row)
    if cp:
        sp = get_socio_pushinpay(cp)
        if sp:
            r = _socio_resolved(cp, sp)
            if r:
                return r
    if usuario_e_socio_responsavel(un):
        sp = get_socio_pushinpay(un)
        if sp:
            r = _socio_resolved(un, sp)
            if r:
                return r
    g = merged_pushinpay_global()
    tok = (g.get("api_token") or "").strip()
    if not tok:
        return None
    return ResolvedPushinPay(
        mode="global",
        socio_billing_username=None,
        api_token=tok,
        api_base=str(g.get("api_base") or _DEFAULT_API),
        webhook_callback_url=global_webhook_url(),
    )


def resolve_pushinpay_for_pedido_row(pedido: dict | None) -> ResolvedPushinPay | None:
    """Consulta/sincronização de pedido já gravado — usa a mesma origem da cobrança."""
    if not pedido:
        return None
    src = str(pedido.get("pushinpay_source") or "global").strip().lower()
    socio = _strip_or_none(pedido.get("socio_billing_username"))
    if src == "socio" and socio:
        sp = queries.get_socio_pushinpay(socio)
        if sp:
            r = _socio_resolved(socio, sp)
            if r:
                return r
        return None
    g = merged_pushinpay_global()
    tok = (g.get("api_token") or "").strip()
    if not tok:
        return None
    return ResolvedPushinPay(
        mode="global",
        socio_billing_username=None,
        api_token=tok,
        api_base=str(g.get("api_base") or _DEFAULT_API),
        webhook_callback_url=global_webhook_url(),
    )
