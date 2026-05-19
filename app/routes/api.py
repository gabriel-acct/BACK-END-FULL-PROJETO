from flask import Blueprint, jsonify, request, send_file
from app.service.login import intentificar_painel
from app.service.segury import payload_from_authorization_header

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

def _credential_from_body(body: dict | None) -> str | None:
    """Credencial direta ou montada a partir de username/password (legado)."""
    if not body:
        return None
    credential = body.get("credential")
    if credential:
        return str(credential).strip()
    username = body.get("username")
    password = body.get("password")
    if username and password is not None:
        return f"painel.local:823:{str(username).strip()}:{password}"
    return None


@api_bp.route("/branding", methods=["GET"])
def branding_public_route():
    """Marca do site (nome, textos, URLs de logo) — público, sem autenticação."""
    try:
        from db.queries_site_branding import get_site_branding
        from app.service.site_branding_public import branding_to_public_api

        data = get_site_branding()
        if not data["status"]:
            return jsonify(data), 500
        branding = branding_to_public_api(data.get("branding") or {})
        return jsonify({"status": True, "branding": branding}), 200
    except Exception as e:
        return jsonify({"status": False, "message": str(e)}), 500


def _send_branding_asset(kind: str):
    from db.queries_site_branding import get_site_branding
    from app.service.site_branding_files import resolve_branding_file

    data = get_site_branding()
    if not data["status"]:
        return jsonify(data), 500
    branding = data.get("branding") or {}
    key = "logo_filename" if kind == "logo" else "favicon_filename"
    path = resolve_branding_file(branding.get(key))
    if not path:
        return jsonify({"status": False, "message": "Arquivo não encontrado"}), 404
    return send_file(path, conditional=True)


@api_bp.route("/branding/logo", methods=["GET"])
def branding_logo_route():
    try:
        return _send_branding_asset("logo")
    except Exception as e:
        return jsonify({"status": False, "message": str(e)}), 500


@api_bp.route("/branding/favicon", methods=["GET"])
def branding_favicon_route():
    try:
        return _send_branding_asset("favicon")
    except Exception as e:
        return jsonify({"status": False, "message": str(e)}), 500


@api_bp.route("/login", methods=["POST"])
def login_route():
    """Login unificado: admin (banco) ou sub-usuário (API) via credencial."""
    from app.security.login_limiter import (
        check_login_allowed,
        client_key_from_request,
        record_login_failure,
        record_login_success,
    )

    try:
        client_key = client_key_from_request(request)
        allowed, block_msg = check_login_allowed(client_key)
        if not allowed:
            return jsonify({"status": False, "message": block_msg}), 429

        body = request.get_json(silent=True) or {}
        credential = _credential_from_body(body)
        if not credential:
            return jsonify({
                "status": False,
                "message": "Informe a credencial (host:porta:usuario:senha)",
            }), 400
        data = intentificar_painel(credential)
        if not data["status"]:
            record_login_failure(client_key)
            return jsonify(data), 400
        record_login_success(client_key)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao identificar painel: {e}",
        }), 500


def _payload_and_user_from_bearer():
    from app.service.sub_usuarios import get_user_by_id
    payload = payload_from_authorization_header(request.headers.get("Authorization"))
    if payload.get("role") == "admin":
        raise PermissionError("Token administrativo não válido nesta rota")
    username = payload.get("sub")
    if not username:
        raise PermissionError("Token malformado")

    user = get_user_by_id(int(username))
    if not user["status"]:
        raise PermissionError(f"Usuário não encontrado: {user['message']}")

    return payload, user


def _authenticated_user_or_error_response():
    """
    Valida Bearer + token + usuário (mesma lógica em todas as rotas protegidas).

    Retorno:
      - Sucesso: ((token_payload, user), None)
      - Erro: (None, (resposta_jsonify, código_http))
    """
    try:
        token_payload, user = _payload_and_user_from_bearer()
    except PermissionError as e:
        return None, (
            jsonify({"is_logged": False, "message": str(e)}),
            403,
        )
    except Exception as e:
        return None, (
            jsonify({"is_logged": False, "message": str(e)}),
            500,
        )
    if not user["status"]:
        return None, (
            jsonify({"is_logged": False, "message": user["message"]}),
            403,
        )
    return (token_payload, user), None


@api_bp.route("/bootstrap", methods=["GET"])
def bootstrap_route():
    """Uma autenticação + dados do painel (perfil, saldo, países, protocolos)."""
    try:
        from concurrent.futures import ThreadPoolExecutor
        from app.service.sub_usuarios import (
            get_all_paises_dict,
            get_balance,
            get_pais_user,
            get_protocolo,
            get_history,
        )

        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, user = ctx
        user_id = str(user["user"]["id"])
        sub = str(token_payload["sub"])

        from db.queires import get_proxy_hostnames_for_dashboard

        with ThreadPoolExecutor(max_workers=6) as pool:
            balance_f = pool.submit(get_balance, user_id)
            countries_f = pool.submit(get_all_paises_dict)
            user_countries_f = pool.submit(get_pais_user, sub)
            protocol_f = pool.submit(get_protocolo, sub)
            history_f = pool.submit(get_history, user_id, 50, 0, "month")
            proxy_hosts_f = pool.submit(get_proxy_hostnames_for_dashboard)
            balance = balance_f.result()
            countries = countries_f.result()
            user_countries = user_countries_f.result()
            protocol = protocol_f.result()
            history = history_f.result()
            proxy_hosts = proxy_hosts_f.result()
        return jsonify({
            "is_logged": True,
            "message": user["message"],
            "profile": user["user"],
            "balance": balance,
            "countries": countries,
            "userCountries": user_countries,
            "protocol": protocol,
            "history": history,
            "proxyHosts": proxy_hosts.get("hosts", []) if proxy_hosts.get("status") else [],
        }), 200
    except Exception as e:
        return jsonify({
            "is_logged": False,
            "message": f"Erro ao carregar painel: {e}",
        }), 500


@api_bp.route("/me", methods=["GET"])
def me_route():
    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    _token_payload, user = ctx
    return jsonify({
        "is_logged": True,
        "message": user["message"],
        "data": user["user"]
    }), 200

@api_bp.route("/balance", methods=["GET"])
def balance_route():
    try:
        from app.service.sub_usuarios import get_balance
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        data = get_balance(str(_user["user"]["id"]))
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao consultar saldo: {e}"
        }), 500

@api_bp.route("/set-pais", methods=["POST"])
def set_pais_route():
    try:
        from app.service.sub_usuarios import set_pais
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        body = request.get_json(silent=True) or {}
        pais = body.get("pais")
        if not pais or not isinstance(pais, list):
            return jsonify({
                "status": False,
                "message": "Campo obrigatório: pais (lista de códigos, ex.: [\"BR\", \"US\"])",
            }), 400
        data = set_pais(int(_user["user"]["id"]), pais)
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao setar país: {e}"
        }), 500

@api_bp.route("/set-threads", methods=["POST"])
def set_threads_route():
    try:
        from app.service.sub_usuarios import set_threads
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        body = request.get_json(silent=True) or {}
        if body.get("threads") is None:
            return jsonify({
                "status": False,
                "message": "Campo obrigatório: threads (número inteiro)",
            }), 400
        data = set_threads(str(token_payload["sub"]), body.get("threads"))
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao setar threads: {e}"
        }), 500

@api_bp.route("/set-protocolo-http-socks5", methods=["POST"])
def set_protocolo_http_socks5_route():
    try:
        from app.service.sub_usuarios import set_protocolo_http_socks5
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        body = request.get_json(silent=True) or {}
        protocolo = body.get("protocolo")
        if protocolo is None:
            return jsonify({
                "status": False,
                "message": "Campo obrigatório: protocolo (lista, ex.: [\"http\", \"socks5\"])",
            }), 400
        if isinstance(protocolo, str):
            protocolo = [protocolo]
        if not isinstance(protocolo, list) or not protocolo:
            return jsonify({
                "status": False,
                "message": "protocolo deve ser uma lista não vazia",
            }), 400
        data = set_protocolo_http_socks5(str(token_payload["sub"]), protocolo)
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao setar protocolo HTTP/SOCKS5: {e}"
        }), 500

@api_bp.route("/get-protocolo", methods=["GET"])
def get_protocolo_route():
    try:
        from app.service.sub_usuarios import get_protocolo
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        data = get_protocolo(str(token_payload["sub"]))
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao consultar protocolo: {e}"
        }), 500

@api_bp.route("/get-history", methods=["GET"])
def get_history_route():
    try:
        from app.service.sub_usuarios import get_history
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        _token_payload, user = ctx
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)
        period = request.args.get("period", default="month", type=str)
        data = get_history(str(user["user"]["id"]), int(limit), int(offset), period)
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao consultar histórico: {e}"
        }), 500


@api_bp.route("/get-all-paises", methods=["GET"])
def get_all_paises_route():
    try:
        from app.service.sub_usuarios import get_all_paises_dict
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        data = get_all_paises_dict()
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao consultar países: {e}"
        }), 500

def _subuser_storage_key(user: dict) -> str:
    """Chave estável para pedidos PIX (id do sub-usuário na API)."""
    nested = user.get("user")
    if isinstance(nested, dict):
        uid = nested.get("id") or nested.get("subuser_id")
        if uid is not None:
            return str(uid).strip()
    uid = user.get("id")
    if uid is not None:
        return str(uid).strip()
    return ""


def _notificacao_subuser_id(token_payload: dict, user: dict) -> str:
    """ID usado em notificações — mesmo valor do JWT sub / pedidos PIX."""
    key = _subuser_storage_key(user)
    if key:
        return key
    return str(token_payload.get("sub") or "").strip()


def _serialize_pedido_row(r: dict, *, include_pix_payload: bool = False) -> dict:
    from datetime import date, datetime

    o = dict(r)
    if not include_pix_payload:
        o.pop("payload_pix", None)
    for k in ("criado_em", "atualizado_em"):
        v = o.get(k)
        if isinstance(v, (datetime, date)):
            o[k] = v.isoformat()
    if o.get("valor_reais") is not None:
        o["valor_reais"] = float(o["valor_reais"])
    if o.get("gb_credito") is not None:
        o["gb_credito"] = float(o["gb_credito"])
    if o.get("preco_id") is not None:
        o["preco_id"] = int(o["preco_id"])
    return o


def _discount_row_public(r: dict) -> dict:
    return {
        "id": int(r["id"]),
        "nome": str(r.get("nome") or ""),
        "gb_minimo": float(r["gb_minimo"]),
        "percentual_desconto": float(r["percentual_desconto"]) if r.get("percentual_desconto") is not None else None,
        "valor_fixo_reais": float(r["valor_fixo_reais"]) if r.get("valor_fixo_reais") is not None else None,
    }


@api_bp.route("/recarga/precos", methods=["GET"])
def recarga_precos_route():
    from app.service.recarga_calc import aplicar_desconto_recarga
    from db import queries_recarga as q

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    _tp, user = ctx

    cfg = q.get_recarga_por_gb_config()
    disc_rows = q.list_recarga_descontos_para_calculo()
    out = {
        "modo": "por_gb",
        "preco_por_gb_reais": cfg["preco_por_gb_reais"],
        "gb_min": cfg["gb_min"],
        "gb_max": cfg["gb_max"],
        "gb_step": cfg["gb_step"],
        "descontos": [_discount_row_public(r) for r in disc_rows],
    }

    gb_q = request.args.get("gb")
    if gb_q is not None and str(gb_q).strip() != "":
        try:
            gb_sim = float(str(gb_q).strip().replace(",", "."))
            out["simulacao"] = aplicar_desconto_recarga(gb_sim, cfg["preco_por_gb_reais"], disc_rows)
        except ValueError:
            pass

    return jsonify(out), 200


@api_bp.route("/recarga/pix/cobranca", methods=["POST"])
def recarga_pix_cobranca_route():
    from flask import current_app

    from app.service.payment_logging import log_payment_event
    from app.service.pushinpay_client import pix_cash_in
    from app.service.pushinpay_credentials import resolve_pushinpay_for_proxy_user
    from app.service.recarga_pix_service import allow_pix_frequency, calcular_cobranca_por_gb
    from db import queries_recarga as q

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_key = _subuser_storage_key(user)

    def _log(ev: str, *, severity: str = "info", meta: dict | None = None, **kw):
        log_payment_event(
            ev,
            "api",
            severity=severity,
            username=sub_key,
            user=user,
            token_payload=tp,
            meta=meta,
            **kw,
        )

    if not allow_pix_frequency(sub_key):
        _log("pix_cobranca_throttle", severity="warn", meta={"motivo": "rate_limit"})
        return jsonify({"error": "Muitas cobranças em pouco tempo. Tente novamente mais tarde."}), 429

    body = request.get_json(silent=True) or {}
    raw_gb = body.get("gb")
    if raw_gb is None or str(raw_gb).strip() == "":
        _log("pix_cobranca_validacao", severity="warn", meta={"erro": "gb_ausente"})
        return jsonify({"error": "Informe o campo gb"}), 400

    try:
        gb_in = float(str(raw_gb).strip().replace(",", "."))
    except ValueError:
        _log("pix_cobranca_validacao", severity="warn", meta={"erro": "gb_invalido", "gb": str(raw_gb)[:32]})
        return jsonify({"error": "gb inválido"}), 400

    calc, calc_err = calcular_cobranca_por_gb(gb_in)
    if calc_err or not calc:
        _log("pix_cobranca_validacao", severity="warn", meta={"erro": calc_err, "gb": gb_in})
        return jsonify({"error": calc_err or "Não foi possível calcular o valor"}), 400

    pp_ctx = resolve_pushinpay_for_proxy_user(user.get("user"))
    if not pp_ctx:
        _log("pix_cobranca_pushinpay_indisponivel", severity="error", meta={"gb": gb_in})
        return jsonify({
            "error": "Pagamento PIX não configurado. O administrador deve cadastrar a PushinPay no painel admin.",
        }), 503

    _log(
        "pix_cobranca_iniciada",
        meta={
            "gb": calc["gb_credito"],
            "valor_reais": calc["valor_reais"],
            "valor_centavos": calc["valor_centavos"],
        },
    )

    ok_pp, payload = pix_cash_in(
        int(calc["valor_centavos"]),
        pp_ctx.webhook_callback_url,
        api_token=pp_ctx.api_token,
        api_base=pp_ctx.api_base,
    )
    if not ok_pp:
        _log("pix_cobranca_pushinpay_erro", severity="error", meta={"detalhe": str(payload)[:500]})
        return jsonify({"error": str(payload)}), 502

    assert isinstance(payload, dict)
    ext_id = str(payload.get("id") or "").strip()
    qr = str(payload.get("qr_code") or "")
    if not ext_id or not qr:
        _log("pix_cobranca_pushinpay_resposta_incompleta", severity="error", meta={"keys": list(payload.keys())[:20]})
        return jsonify({"error": "Resposta incompleta da operadora de pagamento"}), 502

    local_id, db_err = q.insert_recarga_pedido_pix(
        sub_key,
        calc.get("preco_id"),
        float(calc["gb_credito"]),
        float(calc["valor_reais"]),
        ext_id,
        qr,
        pushinpay_source=pp_ctx.mode,
    )
    if not local_id:
        current_app.logger.error("PIX criado (%s) mas falhou INSERT: %s", ext_id[:36], db_err)
        _log(
            "pix_cobranca_orfao",
            severity="error",
            id_externo=ext_id,
            meta={"db_erro": db_err, "valor_reais": calc["valor_reais"], "gb": calc["gb_credito"]},
        )
        return jsonify({
            "error": "Cobrança criada no gateway, mas houve falha ao registrar o pedido.",
            "detalhe": db_err,
        }), 500

    _log(
        "pix_cobranca_criada",
        pedido_id=local_id,
        id_externo=ext_id,
        meta={
            "valor_reais": calc["valor_reais"],
            "gb_credito": calc["gb_credito"],
            "status_gateway": payload.get("status") or "created",
        },
    )

    return jsonify({
        "pedido_id": local_id,
        "id_externo": ext_id,
        "valor_reais": float(calc["valor_reais"]),
        "gb_credito": float(calc["gb_credito"]),
        "status": payload.get("status") or "created",
        "qr_code": qr,
        "qr_code_base64": payload.get("qr_code_base64"),
        "simulacao": calc.get("simulacao"),
    }), 200


@api_bp.route("/recarga/pix/pedidos", methods=["GET"])
def recarga_pix_pedidos_route():
    from db import queries_recarga as q

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    _tp, user = ctx
    rows = q.list_recarga_pedidos_pix_for_user(_subuser_storage_key(user), 40)
    return jsonify(pedidos=[_serialize_pedido_row(dict(r)) for r in rows]), 200


@api_bp.route("/recarga/pix/pedidos/<int:pid>/sincronizar", methods=["POST"])
def recarga_pix_sincronizar_route(pid: int):
    from app.service.payment_logging import allow_sync_frequency, finalize_pix_and_log, log_payment_event
    from app.service.pushinpay_credentials import effective_recarga_pix_sync_max_per_hour
    from app.service.pushinpay_client import get_transaction
    from app.service.pushinpay_credentials import resolve_pushinpay_for_pedido_row
    from db import queries_recarga as q

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_key = _subuser_storage_key(user)
    max_sync = effective_recarga_pix_sync_max_per_hour()

    if not allow_sync_frequency(sub_key, max_per_hour=max_sync):
        log_payment_event(
            "pix_sync_throttle",
            "api",
            severity="warn",
            username=sub_key,
            pedido_id=pid,
            user=user,
            token_payload=tp,
            meta={"motivo": "rate_limit"},
        )
        return jsonify({"error": "Muitas sincronizações. Aguarde alguns minutos."}), 429

    row = q.get_pedido_pix_by_id_for_user(pid, sub_key)
    if not row:
        log_payment_event(
            "pix_sync_pedido_nao_encontrado",
            "api",
            severity="warn",
            username=sub_key,
            pedido_id=pid,
            user=user,
            token_payload=tp,
        )
        return jsonify({"error": "Pedido não encontrado"}), 404

    ext = str(row.get("id_externo") or "").strip()
    if not ext:
        log_payment_event(
            "pix_sync_sem_id_externo",
            "api",
            severity="warn",
            username=sub_key,
            pedido_id=pid,
            user=user,
            token_payload=tp,
        )
        return jsonify({"error": "Pedido sem id externo"}), 400

    pp_ctx = resolve_pushinpay_for_pedido_row(dict(row))
    if not pp_ctx:
        log_payment_event(
            "pix_sync_pushinpay_indisponivel",
            "api",
            severity="error",
            username=sub_key,
            pedido_id=pid,
            id_externo=ext,
            user=user,
            token_payload=tp,
        )
        return jsonify({"error": "Credencial PushinPay não disponível."}), 409

    log_payment_event(
        "pix_sync_iniciada",
        "api",
        username=sub_key,
        pedido_id=pid,
        id_externo=ext,
        user=user,
        token_payload=tp,
        meta={"status_local": row.get("status")},
    )

    ok, data = get_transaction(ext, api_token=pp_ctx.api_token, api_base=pp_ctx.api_base)
    if not ok:
        log_payment_event(
            "pix_sync_pushinpay_erro",
            "api",
            severity="error",
            username=sub_key,
            pedido_id=pid,
            id_externo=ext,
            user=user,
            token_payload=tp,
            meta={"detalhe": str(data)[:500]},
        )
        return jsonify({"error": str(data)}), 502

    assert isinstance(data, dict)
    st = str(data.get("status") or "")
    val = data.get("value")
    try:
        value_cents = None if val is None or (isinstance(val, str) and not val.strip()) else int(round(float(val)))
    except (TypeError, ValueError):
        value_cents = None

    result = finalize_pix_and_log(
        ext,
        st,
        value_cents,
        source="api_sync",
        log_prefix="pix_sync",
        user=user,
        token_payload=tp,
        pedido_id_hint=pid,
        username_hint=sub_key,
    )
    fresh = q.get_pedido_pix_by_id_for_user(pid, sub_key)
    return jsonify({
        "resultado": result,
        "pedido": _serialize_pedido_row(dict(fresh)) if fresh else None,
    }), 200


def _serialize_notificacao_row(r: dict) -> dict:
    from datetime import date, datetime

    o = dict(r)
    for k in ("criado_em",):
        v = o.get(k)
        if isinstance(v, (datetime, date)):
            o[k] = v.isoformat()
    o["lida"] = bool(int(o.get("lida") or 0))
    o["critico_ack"] = bool(int(o.get("critico_ack") or 0))
    return o


@api_bp.route("/notificacoes", methods=["GET"])
def notificacoes_list_route():
    from db import queries_notificacoes as qn

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_id = _notificacao_subuser_id(tp, user)

    items = qn.list_notificacoes_for_subuser(sub_id, limit=80)
    unread = qn.count_unread_for_subuser(sub_id)
    critical = [_serialize_notificacao_row(r) for r in qn.list_critical_pending_for_subuser(sub_id)]

    return jsonify({
        "status": True,
        "notificacoes": [_serialize_notificacao_row(r) for r in items],
        "unread_count": unread,
        "critical_pending": critical,
    }), 200


@api_bp.route("/notificacoes/<int:nid>/lida", methods=["POST"])
def notificacao_lida_route(nid: int):
    from db import queries_notificacoes as qn

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_id = _notificacao_subuser_id(tp, user)
    if not qn.subuser_can_see_notificacao(nid, sub_id):
        return jsonify({"status": False, "message": "Notificação não encontrada"}), 404
    if not qn.mark_notificacao_lida(nid, sub_id):
        return jsonify({"status": False, "message": "Falha ao marcar como lida"}), 500
    return jsonify({"status": True}), 200


@api_bp.route("/notificacoes/<int:nid>", methods=["DELETE"])
def notificacao_ocultar_route(nid: int):
    """Remove da lista apenas para o usuário logado."""
    from db import queries_notificacoes as qn

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_id = _notificacao_subuser_id(tp, user)
    if not qn.subuser_can_see_notificacao(nid, sub_id):
        return jsonify({"status": False, "message": "Notificação não encontrada"}), 404
    if not qn.hide_notificacao_for_subuser(nid, sub_id):
        return jsonify({"status": False, "message": "Falha ao remover notificação"}), 500
    return jsonify({"status": True}), 200


@api_bp.route("/notificacoes/<int:nid>/critico-ack", methods=["POST"])
def notificacao_critico_ack_route(nid: int):
    from db import queries_notificacoes as qn

    ctx, err = _authenticated_user_or_error_response()
    if err:
        body, code = err
        return body, code
    tp, user = ctx
    sub_id = _notificacao_subuser_id(tp, user)
    if not qn.subuser_can_see_notificacao(nid, sub_id):
        return jsonify({"status": False, "message": "Notificação não encontrada"}), 404
    if not qn.mark_critico_ack(nid, sub_id):
        return jsonify({"status": False, "message": "Falha ao confirmar aviso"}), 500
    return jsonify({"status": True}), 200


@api_bp.route("/blocked-hosts", methods=["GET"])
def client_blocked_hosts_list_route():
    """Lista hosts bloqueados do sub-usuário logado."""
    try:
        from app.service.sub_usuarios import get_client_blocked_hosts_payload

        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        _tp, user = ctx
        subuser_id = int(user["user"]["id"])
        data = get_client_blocked_hosts_payload(subuser_id)
        if not data.get("status"):
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"status": False, "message": f"Erro ao listar hosts bloqueados: {e}"}), 500


@api_bp.route("/blocked-hosts", methods=["POST"])
def client_blocked_hosts_add_route():
    """Adiciona domínio ao bloqueio do sub-usuário logado."""
    try:
        from app.service.sub_usuarios import add_client_blocked_host

        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        _tp, user = ctx
        body = request.get_json(silent=True) or {}
        hostname = body.get("hostname")
        if not hostname or not str(hostname).strip():
            return jsonify({"status": False, "message": "Campo obrigatório: hostname"}), 400
        data = add_client_blocked_host(int(user["user"]["id"]), str(hostname))
        if not data.get("status"):
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"status": False, "message": f"Erro ao bloquear host: {e}"}), 500


@api_bp.route("/blocked-hosts", methods=["DELETE"])
def client_blocked_hosts_remove_route():
    """Remove domínio adicionado pelo usuário (hosts do painel não podem ser removidos)."""
    try:
        from app.service.sub_usuarios import remove_client_blocked_host

        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        _tp, user = ctx
        body = request.get_json(silent=True) or {}
        hostname = body.get("hostname")
        if not hostname or not str(hostname).strip():
            return jsonify({"status": False, "message": "Campo obrigatório: hostname"}), 400
        data = remove_client_blocked_host(int(user["user"]["id"]), str(hostname))
        if not data.get("status"):
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"status": False, "message": f"Erro ao remover bloqueio: {e}"}), 500


@api_bp.route("/get-pais-user-default", methods=["GET"])
def get_pais_user_default_route():
    try:
        from app.service.sub_usuarios import get_pais_user
        ctx, err = _authenticated_user_or_error_response()
        if err:
            body, code = err
            return body, code
        token_payload, _user = ctx
        data = get_pais_user(str(token_payload["sub"]))
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao consultar país do usuário: {e}"
        }), 500