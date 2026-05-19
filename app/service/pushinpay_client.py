"""Cliente HTTP PushinPay (PIX)."""
from __future__ import annotations

from typing import Any

import requests
from flask import current_app

from app.service.pushinpay_credentials import merged_pushinpay_global

_PUSHINPAY_DEFAULT_BASE = "https://api.pushinpay.com.br/api"


def _resolve_token(api_token: str | None) -> str:
    if api_token is not None:
        return str(api_token).strip()
    return str(merged_pushinpay_global().get("api_token") or "").strip()


def _pushin_api_base(override_base: str | None = None) -> str:
    if override_base and str(override_base).strip():
        raw = str(override_base).strip().rstrip("/")
    else:
        raw = str(merged_pushinpay_global().get("api_base") or _PUSHINPAY_DEFAULT_BASE).strip().rstrip("/")
    if "pushinpay.com.br" not in raw.lower():
        current_app.logger.warning(
            "PUSHINPAY_API_BASE ignorada: %s — usando %s",
            raw,
            _PUSHINPAY_DEFAULT_BASE,
        )
        return _PUSHINPAY_DEFAULT_BASE
    return raw


def _headers(api_token: str | None = None) -> dict[str, str]:
    token = _resolve_token(api_token)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def pix_cash_in(
    value_centavos: int,
    webhook_url: str | None,
    timeout: int = 45,
    *,
    api_token: str | None = None,
    api_base: str | None = None,
) -> tuple[bool, dict[str, Any] | str]:
    tok = _resolve_token(api_token)
    if not tok:
        return False, "Token PushinPay não configurado — cadastre no painel admin (MySQL)"

    base = _pushin_api_base(api_base)
    url = f"{base}/pix/cashIn"
    body: dict[str, Any] = {"value": int(value_centavos), "split_rules": []}
    if webhook_url:
        body["webhook_url"] = str(webhook_url).strip()

    try:
        r = requests.post(url, json=body, headers=_headers(tok), timeout=timeout)
    except requests.RequestException as e:
        return False, f"Falha de rede com a PushinPay: {e}"

    try:
        data = r.json()
    except ValueError:
        data = {}

    if 200 <= r.status_code < 300:
        if isinstance(data, dict) and data.get("id"):
            return True, data
        return False, "Resposta inválida da PushinPay"

    return False, _extract_error_message(data, r.text) or f"PushinPay HTTP {r.status_code}"


def get_transaction(
    transaction_id: str,
    timeout: int = 30,
    *,
    api_token: str | None = None,
    api_base: str | None = None,
) -> tuple[bool, dict[str, Any] | str]:
    tok = _resolve_token(api_token)
    if not tok:
        return False, "Token PushinPay não configurado — cadastre no painel admin (MySQL)"

    tid = transaction_id.strip()
    if not tid:
        return False, "ID da transação inválido"

    base = _pushin_api_base(api_base)
    candidates = [
        f"{base}/transactions/{tid}",
        f"{base}/pix/transaction/{tid}",
        f"{base}/transaction/{tid}",
    ]

    last_msg = ""
    for url in candidates:
        try:
            r = requests.get(url, headers=_headers(tok), timeout=timeout)
        except requests.RequestException as e:
            return False, f"Falha de rede com a PushinPay: {e}"

        try:
            data = r.json()
        except ValueError:
            data = {}

        if 200 <= r.status_code < 300 and isinstance(data, dict) and data.get("id"):
            return True, data

        last_msg = _extract_error_message(data, r.text) or f"PushinPay HTTP {r.status_code}"
        if r.status_code not in (404, 405):
            return False, last_msg

    return False, last_msg or "Não foi possível consultar a transação na PushinPay"


def _extract_error_message(data: dict | list | Any, raw: str) -> str:
    if isinstance(data, dict):
        if data.get("error"):
            return str(data["error"])
        if data.get("message"):
            return str(data["message"])
        errs = data.get("errors")
        if isinstance(errs, dict) and errs:
            first = next(iter(errs.values()))
            if isinstance(first, list) and first:
                return str(first[0])
    if raw and len(raw) < 500:
        return raw.strip()
    return ""
