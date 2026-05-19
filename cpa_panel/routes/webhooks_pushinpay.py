"""Webhooks públicos (sem JWT) — validar segredo configurado no painel PushinPay."""
from __future__ import annotations

import hmac
import json
import re

from flask import Blueprint, current_app, jsonify, request

from cpa_panel.db import queries
from cpa_panel.services.pushinpay_credentials import merged_pushinpay_global

bp = Blueprint("cpa_webhooks", __name__, url_prefix="/api/webhooks/cpa")

_SOCIO_UN_SAFE = re.compile(r"^[\w.-]{1,128}$")


def _finalize_from_payload(data: dict) -> tuple[dict, int]:
    tid = str(data.get("id") or "").strip()
    status_raw = data.get("status")
    val = data.get("value")
    try:
        if val is None or (isinstance(val, str) and not val.strip()):
            value_cents = None
        else:
            value_cents = int(round(float(val)))
    except (TypeError, ValueError):
        value_cents = None

    if not tid:
        queries.insert_recarga_payment_log(
            "pix_webhook_sem_id",
            "webhook",
            meta={"payload_keys": list(data.keys())[:40]},
        )
        return {"error": "missing_id"}, 400

    queries.insert_recarga_payment_log(
        "pix_webhook_recebido",
        "webhook",
        id_externo=tid,
        meta={
            "status": str(status_raw)[:120],
            "value_cents": value_cents,
            "payload_resumo": json.dumps(data, ensure_ascii=False, default=str)[:4000],
        },
    )

    result = queries.finalize_pix_pedido_from_gateway(tid, str(status_raw or ""), value_cents)

    queries.insert_recarga_payment_log(
        "pix_webhook_finalizacao",
        "webhook",
        id_externo=tid,
        meta={"resultado": result, "status": str(status_raw)[:120], "value_cents": value_cents},
    )

    if result == "value_mismatch":
        current_app.logger.warning(
            "PushinPay webhook: valor divergente do pedido local (transação %s)", tid[:24]
        )
        return {"ok": False, "reason": "value_mismatch"}, 200

    if result == "missing_value":
        current_app.logger.warning(
            "PushinPay webhook: status paid sem campo value (transação %s)", tid[:24]
        )
        return {"ok": False, "reason": "missing_value"}, 200

    if result == "not_found":
        current_app.logger.info("PushinPay webhook: transação %s sem pedido local", tid[:24])
        return {"ok": False, "reason": "unknown_transaction"}, 200

    if result == "pool_blocked":
        current_app.logger.warning(
            "PushinPay webhook: pool do sócio insuficiente para creditar GB (transação %s)", tid[:24]
        )
        return {"ok": False, "reason": "pool_blocked"}, 200

    return {"ok": True, "result": result}, 200


def _validate_header(expected_secret: str, header_name: str, require_secret: bool) -> tuple[bool, str | None]:
    expected_secret = (expected_secret or "").strip()
    header_name = (header_name or "X-Webhook-Token").strip() or "X-Webhook-Token"
    if require_secret and not expected_secret:
        current_app.logger.error("PushinPay webhook: segredo obrigatório e ausente")
        return False, "server_misconfigured"
    if expected_secret:
        received = (request.headers.get(header_name) or "").strip()
        if not hmac.compare_digest(received, expected_secret):
            current_app.logger.warning("PushinPay webhook: header %s inválido", header_name)
            queries.insert_recarga_payment_log(
                "pix_webhook_auth_falhou",
                "webhook",
                meta={"header": header_name},
            )
            return False, "unauthorized"
    elif require_secret:
        return False, "server_misconfigured"
    return True, None


@bp.post("/pushinpay/pix")
def pushinpay_pix():
    g = merged_pushinpay_global()
    require_secret = bool(g["webhook_require_secret"])
    ok, err = _validate_header(str(g["webhook_secret"] or ""), str(g["webhook_header"] or ""), require_secret)
    if not ok:
        code = 503 if err == "server_misconfigured" else 401
        return jsonify(error=err), code

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        queries.insert_recarga_payment_log(
            "pix_webhook_json_invalido",
            "webhook",
            meta={},
        )
        return jsonify(error="invalid_json"), 400

    body, status = _finalize_from_payload(data)
    return jsonify(body), status


@bp.post("/pushinpay/pix/socio/<socio_username>")
def pushinpay_pix_socio(socio_username: str):
    from urllib.parse import unquote

    su = unquote((socio_username or "").strip())[:128]
    if not su or not _SOCIO_UN_SAFE.match(su):
        return jsonify(error="invalid_socio"), 400

    g = merged_pushinpay_global()
    require_secret = bool(g["webhook_require_secret"])
    sp = queries.get_socio_pushinpay(su)
    socio_secret = (sp.get("webhook_secret") or "").strip() if sp else ""

    ok, err = _validate_header(socio_secret, str(g["webhook_header"] or ""), require_secret)
    if not ok:
        code = 503 if err == "server_misconfigured" else 401
        return jsonify(error=err), code

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        queries.insert_recarga_payment_log(
            "pix_webhook_json_invalido",
            "webhook",
            meta={"rota": "socio", "socio": su},
        )
        return jsonify(error="invalid_json"), 400

    body, status = _finalize_from_payload(data)
    return jsonify(body), status
