"""Credenciais e limites PushinPay — somente MySQL (painel_pushinpay_config / painel_recarga_config)."""
from __future__ import annotations

from dataclasses import dataclass

from db import queries_recarga as queries

_DEFAULT_API = "https://api.pushinpay.com.br/api"
_DEFAULTS = {
    "api_token": "",
    "api_base": _DEFAULT_API,
    "site_public_url": "",
    "webhook_secret": "",
    "webhook_header": "X-Webhook-Token",
    "webhook_require_secret": True,
    "webhook_force_secret": True,
    "recarga_pix_max_per_hour": 30,
    "recarga_pix_sync_max_per_hour": 60,
    "max_total_reais": 50000.0,
}


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


def _bool_from_db(val, default: bool = True) -> bool:
    if val is None:
        return default
    try:
        return int(val) == 1
    except (TypeError, ValueError):
        return bool(val)


def merged_pushinpay_global() -> dict:
    """Lê exclusivamente do MySQL. Sem fallback para variáveis de ambiente."""
    row = queries.get_pushinpay_config_row() or {}
    recarga = queries.get_recarga_por_gb_config()

    api_base = _api_base_safe(_strip_or_none(row.get("api_base")) or _DEFAULTS["api_base"])
    site = (_strip_or_none(row.get("site_public_url")) or "").rstrip("/")
    wh_header = _strip_or_none(row.get("webhook_header")) or _DEFAULTS["webhook_header"]

    max_h = row.get("recarga_pix_max_per_hour")
    try:
        max_h = int(max_h) if max_h is not None and int(max_h) > 0 else _DEFAULTS["recarga_pix_max_per_hour"]
    except (TypeError, ValueError):
        max_h = _DEFAULTS["recarga_pix_max_per_hour"]

    sync_h = row.get("recarga_pix_sync_max_per_hour")
    try:
        sync_h = int(sync_h) if sync_h is not None and int(sync_h) > 0 else _DEFAULTS["recarga_pix_sync_max_per_hour"]
    except (TypeError, ValueError):
        sync_h = _DEFAULTS["recarga_pix_sync_max_per_hour"]

    max_total = recarga.get("max_total_reais", _DEFAULTS["max_total_reais"])
    try:
        max_total = float(max_total)
    except (TypeError, ValueError):
        max_total = _DEFAULTS["max_total_reais"]

    return {
        "api_token": (_strip_or_none(row.get("api_token")) or "").strip(),
        "api_base": api_base,
        "site_public_url": site,
        "webhook_secret": (_strip_or_none(row.get("webhook_secret")) or "").strip(),
        "webhook_header": wh_header,
        "webhook_require_secret": _bool_from_db(row.get("webhook_require_secret"), True),
        "webhook_force_secret": _bool_from_db(row.get("webhook_force_secret"), True),
        "recarga_pix_max_per_hour": max_h,
        "recarga_pix_sync_max_per_hour": sync_h,
        "max_total_reais": max_total,
    }


def effective_recarga_pix_max_per_hour() -> int:
    return int(merged_pushinpay_global().get("recarga_pix_max_per_hour") or 30)


def effective_recarga_pix_sync_max_per_hour() -> int:
    return int(merged_pushinpay_global().get("recarga_pix_sync_max_per_hour") or 60)


def effective_recarga_max_total_reais() -> float:
    return float(merged_pushinpay_global().get("max_total_reais") or 50000.0)


def global_webhook_url() -> str | None:
    site = merged_pushinpay_global()["site_public_url"]
    if not site:
        return None
    return f"{site}/api/webhooks/pushinpay/pix"


@dataclass(frozen=True)
class ResolvedPushinPay:
    mode: str
    socio_billing_username: str | None
    api_token: str
    api_base: str
    webhook_callback_url: str | None


def resolve_pushinpay_for_proxy_user(_user_row: dict | None) -> ResolvedPushinPay | None:
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
    return resolve_pushinpay_for_proxy_user(pedido)
