"""Webhooks PushinPay (sem JWT)."""
from __future__ import annotations

import hmac
import json

from flask import Blueprint, current_app, jsonify, request

from app.service.payment_logging import (
    allow_webhook_ip,
    client_ip,
    finalize_pix_and_log,
    log_payment_event,
    lookup_pedido_refs,
    webhook_must_reject_unconfigured,
)
from app.service.pushinpay_credentials import merged_pushinpay_global
bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


def _validate_header(expected_secret: str, header_name: str, require_secret: bool) -> tuple[bool, str | None]:
    expected_secret = (expected_secret or "").strip()
    header_name = (header_name or "X-Webhook-Token").strip() or "X-Webhook-Token"

    if webhook_must_reject_unconfigured() and not expected_secret:
        return False, "server_misconfigured"

    if require_secret and not expected_secret:
        return False, "server_misconfigured"

    if expected_secret:
        received = (request.headers.get(header_name) or "").strip()
        if not hmac.compare_digest(received, expected_secret):
            log_payment_event(
                "pix_webhook_auth_falhou",
                "webhook",
                severity="warn",
                meta={"header": header_name, "ip": client_ip()},
            )
            return False, "unauthorized"

    if not require_secret and not expected_secret:
        log_payment_event(
            "pix_webhook_sem_segredo",
            "webhook",
            severity="error",
            meta={"aviso": "webhook aceito sem segredo — configure no painel admin (MySQL)"},
        )

    return True, None


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
        log_payment_event(
            "pix_webhook_sem_id",
            "webhook",
            severity="warn",
            meta={"payload_keys": list(data.keys())[:40]},
        )
        return {"error": "missing_id"}, 400

    pedido_id, username = lookup_pedido_refs(tid)

    log_payment_event(
        "pix_webhook_recebido",
        "webhook",
        severity="info",
        username=username,
        pedido_id=pedido_id,
        id_externo=tid,
        meta={
            "status": str(status_raw)[:120],
            "value_cents": value_cents,
            "payload_id": tid[:80],
        },
    )

    result = finalize_pix_and_log(
        tid,
        str(status_raw or ""),
        value_cents,
        source="webhook",
        log_prefix="pix_webhook",
        pedido_id_hint=pedido_id,
        username_hint=username,
    )

    if result == "credit_failed":
        current_app.logger.error("PushinPay webhook: falha ao creditar GB (transação %s)", tid[:24])
        return {"ok": False, "reason": "credit_failed"}, 503

    if result == "value_mismatch":
        return {"ok": False, "reason": "value_mismatch"}, 409

    return {"ok": True, "result": result}, 200


@bp.post("/pushinpay/pix")
def pushinpay_pix():
    if not allow_webhook_ip():
        log_payment_event(
            "pix_webhook_rate_limit",
            "webhook",
            severity="warn",
            meta={"ip": client_ip()},
        )
        return jsonify(error="rate_limit"), 429

    g = merged_pushinpay_global()
    ok, err = _validate_header(
        str(g["webhook_secret"] or ""),
        str(g["webhook_header"] or ""),
        bool(g["webhook_require_secret"]),
    )
    if not ok:
        if err == "server_misconfigured":
            log_payment_event(
                "pix_webhook_misconfig",
                "webhook",
                severity="error",
                meta={"motivo": err},
            )
        code = 503 if err == "server_misconfigured" else 401
        return jsonify(error=err), code

    raw = request.get_data(cache=True)
    try:
        data = json.loads(raw.decode("utf-8") if raw else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        log_payment_event(
            "pix_webhook_json_invalido",
            "webhook",
            severity="warn",
            meta={"body_len": len(raw) if raw else 0},
        )
        return jsonify(error="invalid_json"), 400

    if not isinstance(data, dict):
        log_payment_event("pix_webhook_json_invalido", "webhook", severity="warn", meta={"tipo": type(data).__name__})
        return jsonify(error="invalid_json"), 400

    body, status = _finalize_from_payload(data)
    return jsonify(body), status
