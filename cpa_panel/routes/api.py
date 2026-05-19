from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from cpa_panel.db import queries as db_queries
from cpa_panel.security import TokenInvalidError, issue_token, payload_from_authorization_header
from cpa_panel.services.auth_service import authenticate_port_user_pass, parse_porta_usuario_senha, user_to_dashboard
from cpa_panel.services.date_range import normalize_day_range
from cpa_panel.services.rbac_service import admin_block_for_me, can_view_own_proxy_logs, compute_rbac, has_perm

bp = Blueprint("cpa_api", __name__, url_prefix="/api")


def _resolve_effective_socio_me_routes(request, user, rbac: dict) -> dict:
    """
    Quem é o «sócio efetivo» para rotas /api/me/socio/*:
    - conta sócio de topo → ela mesma;
    - cargo dono (bypass) → query ?socio=username ou modo pick (sem param).
    """
    from cpa_panel.db import queries as q

    actor = str(user.get("username") or "").strip()
    if q.usuario_e_socio_responsavel(actor):
        return {
            "ok": True,
            "effective": actor,
            "pick_socio": False,
            "read_only_view_as": False,
            "socios": None,
            "http_error": None,
        }
    if not rbac.get("bypass_all"):
        return {
            "ok": False,
            "effective": None,
            "pick_socio": False,
            "read_only_view_as": False,
            "socios": None,
            "http_error": ("Apenas contas sócio podem usar esta área.", 403),
        }
    raw = (request.args.get("socio") or "").strip()
    if not raw:
        return {
            "ok": True,
            "effective": None,
            "pick_socio": True,
            "read_only_view_as": True,
            "socios": q.list_socios_topo_para_selecao_dono(),
            "http_error": None,
        }
    if not q.usuario_e_socio_responsavel(raw):
        return {
            "ok": False,
            "effective": None,
            "pick_socio": False,
            "read_only_view_as": False,
            "socios": None,
            "http_error": (
                f"«{raw}» não é um sócio de topo válido (cargo sócio, sem conta criadora).",
                400,
            ),
        }
    return {
        "ok": True,
        "effective": raw,
        "pick_socio": False,
        "read_only_view_as": True,
        "socios": None,
        "http_error": None,
    }


def _socio_me_mutacao_bloqueada_para_dono(rbac: dict, user: dict) -> bool:
    """Dono em bypass não altera rede de sócio por estas rotas (só leitura com ?socio=)."""
    from cpa_panel.db import queries as q

    actor = str(user.get("username") or "").strip()
    return bool(rbac.get("bypass_all") and not q.usuario_e_socio_responsavel(actor))


def _serialize_ts(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _payload_and_user_from_bearer():
    from cpa_panel.db.queries import get_user_for_auth, get_users

    payload = payload_from_authorization_header(request.headers.get("Authorization"))
    username = payload.get("sub")
    porta_token = payload.get("porta")
    if not username or porta_token is None:
        raise PermissionError("Token malformado")

    user = get_user_for_auth(str(username)) or get_users(str(username))
    if not user:
        raise PermissionError("Usuário não encontrado")
    if int(user.get("porta") or 0) != int(porta_token):
        raise PermissionError("Sessão inconsistente — faça login novamente")

    return payload, user


def _user_from_bearer():
    _, user = _payload_and_user_from_bearer()
    return user


@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.get("/blocked-hosts")
def public_blocked_hosts():
    """Lista de domínios bloqueados para o gateway/proxy aplicar filtro de destino."""
    from cpa_panel.db import queries as q

    domains = q.list_blocked_domains_active_public()
    return jsonify(domains=domains)


@bp.post("/auth/login")
def login():
    from app.security.login_limiter import (
        check_login_allowed,
        client_key_from_request,
        record_login_failure,
        record_login_success,
    )

    client_key = client_key_from_request(request)
    allowed, block_msg = check_login_allowed(client_key)
    if not allowed:
        return jsonify(error=block_msg), 429

    data = request.get_json(silent=True) or {}
    credential = data.get("credential", "")
    try:
        porta, username, senha = parse_porta_usuario_senha(str(credential))
        user = authenticate_port_user_pass(porta, username, senha)
    except ValueError as e:
        record_login_failure(client_key)
        return jsonify(error=str(e)), 400
    except PermissionError as e:
        record_login_failure(client_key)
        return jsonify(error=str(e)), 401

    record_login_success(client_key)
    token = issue_token(user["username"], int(user["porta"]))
    return jsonify(access_token=token, token_type="bearer")


@bp.get("/me")
def me():
    try:
        token_payload, user = _payload_and_user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    payload = user_to_dashboard(user)
    admin_block = admin_block_for_me(user)
    if token_payload.get("imp"):
        # Personificação: só experiência de cliente; sem área admin nem CEO no painel.
        rbac_viewed = compute_rbac(user)
        admin_block = {
            "has_access": False,
            "bypass_all": False,
            "cargo_slug": admin_block.get("cargo_slug"),
            "cargo_nome": admin_block.get("cargo_nome"),
            "permissions": [],
            "socio_panel": False,
            "socio_relatorio": False,
            "access_proxy_logs": can_view_own_proxy_logs(user, rbac_viewed),
        }
        imp_by = token_payload.get("imp_by")
        payload["impersonation"] = {"by_username": str(imp_by) if imp_by is not None else ""}
    payload["admin"] = admin_block
    from cpa_panel.db import queries as q

    socio_top = bool(admin_block.get("socio_panel") and q.usuario_e_socio_responsavel(user["username"]))
    if socio_top:
        alloc = q.sum_limite_gb_criados_por(user["username"], exceto_username=None)
        pool = float(user.get("limite_gb") or 0)
        payload["socio_pool"] = {
            "limite_gb": pool,
            "alocado_gb": round(alloc, 6),
            "disponivel_gb": max(0.0, round(pool - alloc, 6)),
            "gateway_porta": int(user.get("porta") or 0),
        }
    try:
        payload["dashboard_proxy_hosts"] = db_queries.effective_dashboard_proxy_hostnames_for_user(user)
    except Exception:
        payload["dashboard_proxy_hosts"] = []
    branding = db_queries.resolve_panel_branding_payload(user)
    if branding:
        payload["panel_branding"] = branding
    if socio_top:
        from cpa_panel.services.pushinpay_credentials import merged_pushinpay_global, socio_webhook_url

        sp = db_queries.get_socio_pushinpay(user["username"])
        merged_pp = merged_pushinpay_global()
        site = merged_pp.get("site_public_url") or ""
        payload["socio_pushinpay"] = {
            "configured": bool(sp and (sp.get("api_token") or "").strip()),
            "webhook_url": socio_webhook_url(user["username"]) if site else None,
            "webhook_header": merged_pp.get("webhook_header") or "X-Webhook-Token",
        }
    return jsonify(payload)


def _parse_panel_branding_from_body(body: dict) -> tuple[str | None, str | None, str | None, str | None]:
    """Valida título/subtítulo/logo para marca do sócio. Retorna (titulo, subtitulo, logo_url, erro)."""
    from urllib.parse import urlparse

    if not isinstance(body, dict):
        return None, None, None, "JSON inválido"

    titulo_raw = body.get("titulo_sidebar", body.get("titulo"))
    subtitulo_raw = body.get("subtitulo_sidebar", body.get("subtitulo"))
    logo_raw = body.get("logo_url", body.get("logo"))

    titulo_s = "" if titulo_raw is None else str(titulo_raw).strip()
    if len(titulo_s) > 64:
        return None, None, None, "titulo_sidebar até 64 caracteres"
    subtitulo_s = "" if subtitulo_raw is None else str(subtitulo_raw).strip()
    if len(subtitulo_s) > 96:
        return None, None, None, "subtitulo_sidebar até 96 caracteres"

    logo_s = ""
    if logo_raw is not None:
        logo_s = str(logo_raw).strip()
        if logo_s:
            if len(logo_s) > 768:
                return None, None, None, "logo_url longo demais"
            p = urlparse(logo_s)
            if p.scheme.lower() != "https":
                return None, None, None, "logo_url deve usar HTTPS"
            host = (p.netloc or "").strip()
            if not host:
                return None, None, None, "logo_url inválida"

    return titulo_s or None, subtitulo_s or None, logo_s or None, None


def _discount_row_public(row):
    pct = row.get("percentual_desconto")
    fix = row.get("valor_fixo_reais")
    return {
        "id": int(row["id"]),
        "nome": row.get("nome") or "",
        "gb_minimo": float(row["gb_minimo"]),
        "percentual_desconto": float(pct) if pct is not None else None,
        "valor_fixo_reais": float(fix) if fix is not None else None,
    }


@bp.get("/recarga/precos")
def recarga_precos():
    from cpa_panel.db import queries
    from cpa_panel.services.recarga_calc import aplicar_desconto_recarga

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    cfg = queries.get_recarga_por_gb_config()
    disc_rows = queries.list_recarga_descontos_para_calculo()
    descontos = [_discount_row_public(r) for r in disc_rows]

    gb_max_cfg = float(cfg["gb_max"])
    gb_min_cfg = float(cfg["gb_min"])
    out = {
        "modo": "por_gb",
        "preco_por_gb_reais": cfg["preco_por_gb_reais"],
        "gb_min": cfg["gb_min"],
        "gb_max": cfg["gb_max"],
        "gb_step": cfg["gb_step"],
        "descontos": descontos,
        "gb_max_efetivo": gb_max_cfg,
    }

    cp = queries._criado_por_str(user)  # noqa: SLF001
    if cp:
        d = queries.pool_disponivel_gb_socio(cp)
        out["socio_criador_username"] = cp
        out["socio_pool_disponivel_gb"] = round(float(d), 6)
        if d < gb_min_cfg - 1e-9:
            out["socio_pool_bloqueado"] = True
            out["gb_max_efetivo"] = gb_min_cfg
        else:
            out["socio_pool_bloqueado"] = False
            out["gb_max_efetivo"] = min(gb_max_cfg, float(d))

    gb_q = request.args.get("gb")
    if gb_q is not None and str(gb_q).strip() != "":
        try:
            gb_sim = float(str(gb_q).strip().replace(",", "."))
            out["simulacao"] = aplicar_desconto_recarga(gb_sim, cfg["preco_por_gb_reais"], disc_rows)
        except ValueError:
            pass

    return jsonify(out)


def _serialize_pedido_row(r: dict) -> dict:
    o = dict(r)
    o["criado_em"] = _serialize_ts(o.get("criado_em"))
    o["atualizado_em"] = _serialize_ts(o.get("atualizado_em"))
    if "valor_reais" in o and o["valor_reais"] is not None:
        o["valor_reais"] = float(o["valor_reais"])
    if "gb_credito" in o and o["gb_credito"] is not None:
        o["gb_credito"] = float(o["gb_credito"])
    if o.get("preco_id") is not None:
        o["preco_id"] = int(o["preco_id"])
    if o.get("pushinpay_source") is not None:
        o["pushinpay_source"] = str(o["pushinpay_source"])
    if "socio_billing_username" in o:
        o["socio_billing_username"] = o["socio_billing_username"] if o["socio_billing_username"] is not None else None
    return o


@bp.post("/recarga/pix/cobranca")
def recarga_pix_cobranca():
    from cpa_panel.db import queries as q
    from cpa_panel.services.pushinpay_client import pix_cash_in
    from cpa_panel.services.pushinpay_credentials import resolve_pushinpay_for_proxy_user
    from cpa_panel.services.recarga_pix_service import (
        allow_pix_frequency,
        calcular_cobranca_por_gb,
        calcular_cobranca_preco_fixo,
        mensagem_recarga_bloqueada_pool_socio,
    )

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    if not allow_pix_frequency(user["username"]):
        q.insert_recarga_payment_log(
            "pix_cobranca_throttle",
            "api",
            username=user["username"],
            meta={"motivo": "rate_limit"},
        )
        return jsonify(error="Muitas cobranças em pouco tempo. Tente novamente mais tarde."), 429

    body = request.get_json(silent=True) or {}
    raw_gb = body.get("gb")
    raw_preco = body.get("preco_id")

    has_gb = raw_gb is not None and str(raw_gb).strip() != ""
    has_preco = raw_preco is not None and str(raw_preco).strip() != ""

    if has_gb == has_preco:
        q.insert_recarga_payment_log(
            "pix_cobranca_validacao",
            "api",
            username=user["username"],
            meta={"erro": "gb_ou_preco_obrigatorio"},
        )
        return jsonify(error="Informe exatamente um dos campos: gb ou preco_id"), 400

    if has_gb:
        try:
            gb_in = float(str(raw_gb).strip().replace(",", "."))
        except ValueError:
            q.insert_recarga_payment_log(
                "pix_cobranca_validacao",
                "api",
                username=user["username"],
                meta={"erro": "gb_invalido"},
            )
            return jsonify(error="gb inválido"), 400
        calc, err = calcular_cobranca_por_gb(gb_in)
    else:
        try:
            pid = int(raw_preco)
        except (TypeError, ValueError):
            q.insert_recarga_payment_log(
                "pix_cobranca_validacao",
                "api",
                username=user["username"],
                meta={"erro": "preco_id_invalido"},
            )
            return jsonify(error="preco_id inválido"), 400
        calc, err = calcular_cobranca_preco_fixo(pid)

    if err or not calc:
        q.insert_recarga_payment_log(
            "pix_cobranca_calculo_falhou",
            "api",
            username=user["username"],
            meta={"erro": err or "calc"},
        )
        return jsonify(error=err or "Não foi possível calcular o valor"), 400

    pool_err = mensagem_recarga_bloqueada_pool_socio(user, float(calc["gb_credito"]))
    if pool_err:
        cp = q._criado_por_str(user)  # noqa: SLF001
        q.insert_recarga_payment_log(
            "pix_cobranca_pool_excedido",
            "api",
            username=user["username"],
            meta={
                "erro": pool_err,
                "gb_credito": float(calc["gb_credito"]),
                "socio": cp,
                "disponivel_gb": q.pool_disponivel_gb_socio(cp) if cp else None,
            },
        )
        return jsonify(error=pool_err, code="socio_pool_excedido"), 400

    q.insert_recarga_payment_log(
        "pix_cobranca_iniciada",
        "api",
        username=user["username"],
        meta={
            "valor_centavos": int(calc["valor_centavos"]),
            "valor_reais": float(calc["valor_reais"]),
            "gb_credito": float(calc["gb_credito"]),
            "preco_id": calc.get("preco_id"),
            "modo": "gb" if has_gb else "preco_fixo",
        },
    )

    pp_ctx = resolve_pushinpay_for_proxy_user(user)
    if not pp_ctx:
        q.insert_recarga_payment_log(
            "pix_cobranca_sem_gateway",
            "api",
            username=user["username"],
            meta={"motivo": "pushinpay_nao_configurado"},
        )
        return jsonify(
            error="Pagamento PIX não configurado. O administrador deve cadastrar a PushinPay no painel admin "
            "ou o sócio deve informar a própria conta em Configurações.",
        ), 503

    hook = pp_ctx.webhook_callback_url
    ok_pp, payload = pix_cash_in(
        int(calc["valor_centavos"]),
        hook,
        api_token=pp_ctx.api_token,
        api_base=pp_ctx.api_base,
    )
    if not ok_pp:
        q.insert_recarga_payment_log(
            "pix_gateway_erro",
            "api",
            username=user["username"],
            meta={"pushinpay": str(payload)[:2000]},
        )
        return jsonify(error=str(payload)), 502

    assert isinstance(payload, dict)
    ext_id = str(payload.get("id") or "").strip()
    qr = str(payload.get("qr_code") or "")
    if not ext_id or not qr:
        q.insert_recarga_payment_log(
            "pix_gateway_resposta_invalida",
            "api",
            username=user["username"],
            id_externo=ext_id or None,
            meta={"tem_id": bool(ext_id), "tem_qr": bool(qr)},
        )
        return jsonify(error="Resposta incompleta da operadora de pagamento"), 502

    local_id, db_err = q.insert_recarga_pedido_pix(
        user["username"],
        calc.get("preco_id"),
        float(calc["gb_credito"]),
        float(calc["valor_reais"]),
        ext_id,
        qr,
        pushinpay_source=pp_ctx.mode,
        socio_billing_username=pp_ctx.socio_billing_username,
    )
    if not local_id:
        current_app.logger.error(
            "PIX PushinPay criado (%s) mas falhou INSERT pedido local: %s",
            ext_id[:36],
            db_err or "?",
        )
        q.insert_recarga_payment_log(
            "pix_pedido_insert_falhou",
            "api",
            username=user["username"],
            id_externo=ext_id,
            meta={"db_erro": (db_err or "")[:4000]},
        )
        return jsonify(
            error="Cobrança criada no gateway, mas houve falha ao registrar o pedido no banco.",
            id_externo=ext_id,
            detalhe=db_err,
        ), 500

    q.insert_recarga_payment_log(
        "pix_pedido_criado",
        "api",
        username=user["username"],
        pedido_id=int(local_id),
        id_externo=ext_id,
        meta={
            "status_gateway": str(payload.get("status") or "created"),
            "valor_reais": float(calc["valor_reais"]),
            "gb_credito": float(calc["gb_credito"]),
        },
    )

    out = {
        "pedido_id": local_id,
        "id_externo": ext_id,
        "valor_reais": float(calc["valor_reais"]),
        "gb_credito": float(calc["gb_credito"]),
        "status": payload.get("status") or "created",
        "qr_code": qr,
        "qr_code_base64": payload.get("qr_code_base64"),
        "simulacao": calc.get("simulacao"),
    }
    return jsonify(out)


@bp.get("/recarga/pix/pedidos")
def recarga_pix_pedidos_list():
    from cpa_panel.db import queries as q

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rows = q.list_recarga_pedidos_pix_for_user(user["username"], 40)
    return jsonify(pedidos=[_serialize_pedido_row(dict(r)) for r in rows])


@bp.get("/recarga/pix/pedidos/<int:pid>")
def recarga_pix_pedido_detalhe(pid: int):
    from cpa_panel.db import queries as q

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    row = q.get_pedido_pix_by_id_for_user(pid, user["username"])
    if not row:
        return jsonify(error="Pedido não encontrado"), 404
    o = _serialize_pedido_row(dict(row))
    return jsonify(o)


@bp.post("/recarga/pix/pedidos/<int:pid>/sincronizar")
def recarga_pix_pedido_sincronizar(pid: int):
    from cpa_panel.db import queries as q
    from cpa_panel.services.pushinpay_client import get_transaction
    from cpa_panel.services.pushinpay_credentials import resolve_pushinpay_for_pedido_row

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    row = q.get_pedido_pix_by_id_for_user(pid, user["username"])
    if not row:
        q.insert_recarga_payment_log(
            "pix_sincronizar_pedido_nao_encontrado",
            "api",
            username=user["username"],
            pedido_id=pid,
            meta={},
        )
        return jsonify(error="Pedido não encontrado"), 404

    ext = str(row.get("id_externo") or "").strip()
    if not ext:
        q.insert_recarga_payment_log(
            "pix_sincronizar_sem_id_externo",
            "api",
            username=user["username"],
            pedido_id=pid,
            meta={},
        )
        return jsonify(error="Pedido sem id externo"), 400

    q.insert_recarga_payment_log(
        "pix_sincronizar_inicio",
        "api",
        username=user["username"],
        pedido_id=pid,
        id_externo=ext,
        meta={"status_local": str(row.get("status") or "")},
    )

    pp_ctx = resolve_pushinpay_for_pedido_row(dict(row))
    if not pp_ctx:
        q.insert_recarga_payment_log(
            "pix_sincronizar_sem_credencial",
            "api",
            username=user["username"],
            pedido_id=pid,
            id_externo=ext,
            meta={"pushinpay_source": row.get("pushinpay_source"), "socio": row.get("socio_billing_username")},
        )
        return jsonify(
            error="Credencial PushinPay deste pedido não está mais disponível (ex.: conta do sócio removida).",
        ), 409

    ok, data = get_transaction(ext, api_token=pp_ctx.api_token, api_base=pp_ctx.api_base)
    if not ok:
        q.insert_recarga_payment_log(
            "pix_sincronizar_consulta_gateway_falhou",
            "api",
            username=user["username"],
            pedido_id=pid,
            id_externo=ext,
            meta={"erro": str(data)[:2000]},
        )
        return jsonify(error=str(data)), 502

    assert isinstance(data, dict)
    st = str(data.get("status") or "")
    val = data.get("value")
    try:
        if val is None or (isinstance(val, str) and not val.strip()):
            value_cents = None
        else:
            value_cents = int(round(float(val)))
    except (TypeError, ValueError):
        value_cents = None

    result = q.finalize_pix_pedido_from_gateway(ext, st, value_cents)
    fresh = q.get_pedido_pix_by_id_for_user(pid, user["username"])
    q.insert_recarga_payment_log(
        "pix_sincronizar_resultado",
        "api",
        username=user["username"],
        pedido_id=pid,
        id_externo=ext,
        meta={
            "resultado": result,
            "status_remoto": st,
            "value_cents": value_cents,
        },
    )
    return jsonify(
        result=result,
        pedido=_serialize_pedido_row(dict(fresh)) if fresh else None,
    )


@bp.get("/me/logs")
def me_logs():
    from cpa_panel.db.queries import (
        ME_LOGS_CAP,
        ME_LOGS_PAGE_SIZE,
        count_proxy_logs_capped,
        list_proxy_logs_paginated,
    )

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    if not can_view_own_proxy_logs(user, rbac):
        return jsonify(error="Sem permissão para histórico de acessos da conta."), 403

    raw_page = request.args.get("page", "0")
    try:
        page = int(raw_page)
    except ValueError:
        page = 0

    df = request.args.get("date_from") or request.args.get("from")
    dt = request.args.get("date_to") or request.args.get("to")
    ca, cb = normalize_day_range(df, dt)

    rows = list_proxy_logs_paginated(
        user["username"],
        page=page,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total_in_window = count_proxy_logs_capped(
        user["username"],
        created_after=ca,
        created_before_exclusive=cb,
    )
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)

    return jsonify(
        logs=out,
        page=page,
        page_size=ME_LOGS_PAGE_SIZE,
        max_logs=ME_LOGS_CAP,
        total_in_window=total_in_window,
    )


@bp.get("/me/paises")
def me_paises_list():
    """Lista países ativos para seleção nas configurações da conta."""
    from cpa_panel.db import queries as q

    try:
        _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rows = q.list_paises_para_painel()
    out = []
    for r in rows or []:
        iso = r.get("codigo_iso2")
        out.append(
            {
                "id": int(r["id"]),
                "nome": str(r.get("nome") or ""),
                "codigo_iso2": str(iso) if iso else None,
            }
        )
    return jsonify(paises=out)


@bp.patch("/me/pais")
def me_pais_patch():
    from cpa_panel.db import queries as q

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    body = request.get_json(silent=True) or {}
    raw_pid = body.get("pais_id", body.get("pais"))

    if raw_pid is None or (isinstance(raw_pid, str) and raw_pid.strip() == ""):
        pais_set: int | None = None
    else:
        try:
            pais_set = int(raw_pid)
        except (TypeError, ValueError):
            return jsonify(error="pais_id inválido"), 400

    ok, err = q.update_usuario_pais(user["username"], pais_set)
    if not ok:
        hint = err or "Confira migrações sql/painel_paises.sql e sql/usuarios_proxy_pais_id.sql no banco"
        return jsonify(error=hint), 400

    from cpa_panel.db.queries import get_user_for_auth, get_users as get_users_plain

    dashboard_user = get_user_for_auth(user["username"]) or get_users_plain(user["username"]) or user
    return jsonify(user_to_dashboard(dashboard_user))


@bp.patch("/me/threads")
def me_threads_patch():
    from cpa_panel.db import queries as q

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    body = request.get_json(silent=True) or {}
    raw = body.get("threads", body.get("thread_count"))
    try:
        threads_val = int(raw)
    except (TypeError, ValueError):
        return jsonify(error="Informe threads como número inteiro"), 400

    ok, err = q.upsert_usuario_threads(user["username"], threads_val)
    if not ok:
        hint = err or "Confira a migração sql/painel_usuario_threads.sql no banco"
        return jsonify(error=hint), 400

    from cpa_panel.db.queries import get_user_for_auth, get_users as get_users_plain

    dashboard_user = get_user_for_auth(user["username"]) or get_users_plain(user["username"]) or user
    return jsonify(user_to_dashboard(dashboard_user))


@bp.patch("/me/panel-branding")
def me_panel_branding_patch():
    from cpa_panel.db import queries as dbq

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    if not dbq.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio podem definir marca do painel."), 403

    body = request.get_json(silent=True) or {}
    titulo, subtitulo, logo_url, ber = _parse_panel_branding_from_body(body)
    if ber:
        return jsonify(error=ber), 400

    ok, uerr = dbq.upsert_socio_panel_branding(user["username"], titulo, subtitulo, logo_url)
    if not ok:
        hint = (
            uerr
            or "Confira migração sql/painel_socio_panel_branding.sql e se a conta é sócio de topo."
        )
        return jsonify(error=hint), 400

    t_sh = str(titulo or "").strip()[:80]
    s_sh = str(subtitulo or "").strip()[:80]
    logo_sh = "sim" if str(logo_url or "").strip() else "não"
    dbq.insert_audit_log(
        user["username"],
        "socio.panel_branding",
        "panel_branding",
        user["username"],
        f"titulo={t_sh!r} subtitulo={s_sh!r} logo={logo_sh}",
    )

    branding = dbq.resolve_panel_branding_payload(user)
    return jsonify(panel_branding=branding)


def _mask_pushin_token_preview(val: str | None) -> str | None:
    if not val or not str(val).strip():
        return None
    s = str(val).strip()
    if len(s) <= 6:
        return "******"
    return f"******{s[-4:]}"


@bp.get("/me/pushinpay-socio")
def me_pushinpay_socio_get():
    from cpa_panel.db import queries as dbq
    from cpa_panel.services.pushinpay_credentials import merged_pushinpay_global, socio_webhook_url

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    if not dbq.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio podem consultar esta configuração."), 403

    sp = dbq.get_socio_pushinpay(user["username"])
    g = merged_pushinpay_global()
    site = (g.get("site_public_url") or "").strip()
    wh = socio_webhook_url(user["username"]) if site else None
    return jsonify(
        configured=bool(sp and (sp.get("api_token") or "").strip()),
        api_base=(sp.get("api_base") or "").strip() or None,
        api_token_preview=_mask_pushin_token_preview((sp.get("api_token") or "").strip() if sp else None),
        webhook_secret_configured=bool(sp and (sp.get("webhook_secret") or "").strip()),
        webhook_url=wh,
        webhook_header=g.get("webhook_header") or "X-Webhook-Token",
        instrucoes_webhook="No painel PushinPay do sócio, configure o webhook para a URL acima e o mesmo segredo em "
        "«header» indicado. Deve coincidir com o campo «segredo do webhook» salvo aqui.",
    )


@bp.patch("/me/pushinpay-socio")
def me_pushinpay_socio_patch():
    from cpa_panel.db import queries as dbq

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    if not dbq.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio podem alterar esta configuração."), 403

    body = request.get_json(silent=True) or {}
    if body.get("clear") is True:
        dbq.delete_socio_pushinpay(user["username"])
        dbq.insert_audit_log(
            user["username"],
            "socio.pushinpay.clear",
            "pushinpay_socio",
            user["username"],
            None,
        )
        return jsonify(ok=True, cleared=True)

    api_token_raw = body.get("api_token")
    existing = dbq.get_socio_pushinpay(user["username"])
    ex = existing or {}
    if api_token_raw is None or not str(api_token_raw).strip():
        if not ex.get("api_token") or not str(ex.get("api_token")).strip():
            return jsonify(error="Informe api_token (Bearer da PushinPay do sócio)."), 400
        new_tok = str(ex.get("api_token") or "").strip()
    else:
        new_tok = str(api_token_raw).strip()

    if "webhook_secret" in body:
        ws_raw = body.get("webhook_secret")
        ws = None if ws_raw is None or str(ws_raw).strip() == "" else str(ws_raw).strip()
    else:
        ws = (ex.get("webhook_secret") or "").strip() or None

    if "api_base" in body:
        ab_raw = body.get("api_base")
        ab = None if ab_raw is None or str(ab_raw).strip() == "" else str(ab_raw).strip()[:256]
    else:
        ab = (ex.get("api_base") or "").strip()[:256] or None

    ok, uerr = dbq.upsert_socio_pushinpay(user["username"], new_tok, ws, ab)
    if not ok:
        return jsonify(error=uerr or "Não foi possível salvar"), 400

    dbq.insert_audit_log(
        user["username"],
        "socio.pushinpay.upsert",
        "pushinpay_socio",
        user["username"],
        "token e webhook atualizados",
    )
    return jsonify(ok=True)


@bp.patch("/me/port")
def me_port():
    from cpa_panel.db.queries import update_user_port_exclusive

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    body = request.get_json(silent=True) or {}
    raw = body.get("porta", body.get("port"))
    try:
        new_port = int(raw)
    except (TypeError, ValueError):
        return jsonify(error="Informe uma porta numérica válida"), 400

    ok, msg = update_user_port_exclusive(user["username"], int(user["porta"]), new_port)
    if not ok:
        return jsonify(error=msg or "Não foi possível alterar a porta"), 409

    from cpa_panel.db import queries as q

    if q.usuario_e_socio_responsavel(user["username"]):
        q.sync_porta_filhos_criados_por(user["username"], new_port)

    token = issue_token(user["username"], new_port)
    fresh = user.copy()
    fresh["porta"] = new_port
    return jsonify(access_token=token, token_type="bearer", dashboard=user_to_dashboard(fresh))


@bp.get("/me/socio/users")
def socio_list_users():
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.users.view")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            pick_socio=True,
            socios=ctx.get("socios") or [],
            users=[],
            pool_limite_gb=0.0,
            pool_alocado_gb=0.0,
            pool_disponivel_gb=0.0,
            gateway_porta=0,
            read_only_view_as=True,
        )

    effective = str(ctx["effective"] or "").strip()
    socio_row = q.get_user_for_auth(effective) or q.get_users(effective) or {}
    rows = q.list_usuarios_criados_por(effective)
    alloc = q.sum_limite_gb_criados_por(effective, exceto_username=None)
    pool = float(socio_row.get("limite_gb") or 0)
    out = []
    for r in rows or []:
        out.append(
            {
                "username": r.get("username"),
                "porta": int(r["porta"]) if r.get("porta") is not None else None,
                "status": int(r.get("status") or 0),
                "limite_gb": float(r.get("limite_gb") or 0),
                "usado_bytes": int(r.get("usado_bytes") or 0),
            }
        )
    return jsonify(
        pick_socio=False,
        socios=None,
        read_only_view_as=bool(ctx.get("read_only_view_as")),
        users=out,
        pool_limite_gb=pool,
        pool_alocado_gb=round(alloc, 6),
        pool_disponivel_gb=max(0.0, round(pool - alloc, 6)),
        gateway_porta=int(socio_row.get("porta") or 0),
    )


@bp.post("/me/socio/users")
def socio_create_user():
    from cpa_panel.db import queries as dbq
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.users.create")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    if _socio_me_mutacao_bloqueada_para_dono(rbac, user):
        return jsonify(
            error="Criação de clientes só pode ser feita logado como conta sócio de topo (não pela visualização do dono).",
        ), 403
    if not dbq.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio podem criar usuários aqui."), 403

    body = request.get_json(silent=True) or {}
    if body.get("username") is not None or body.get("senha") is not None:
        un = str(body.get("username") or "").strip()
        pw = body.get("senha")
        if un or (pw is not None and str(pw).strip() != ""):
            return jsonify(
                error="Não envie usuário nem senha: o servidor só gera credenciais aleatórias."
            ), 400
    raw_qtd = body.get("quantidade", body.get("qtd", 1))
    try:
        quantidade = int(raw_qtd)
    except (TypeError, ValueError):
        return jsonify(error="quantidade inválida (use inteiro positivo)."), 400
    try:
        limite_gb = float(body.get("limite_gb", 0))
    except (TypeError, ValueError):
        return jsonify(error="limite_gb inválido"), 400

    raw_porta = body.get("porta", body.get("port"))
    try:
        porta_inf = int(raw_porta)
    except (TypeError, ValueError):
        return jsonify(error="Informe a porta do gateway (823 ou 824) igual à da sua conta."), 400

    ok, msg, created = dbq.bulk_create_filhos_socio_aleatorio(
        user["username"],
        quantidade,
        limite_gb,
        porta_inf,
    )
    if not ok:
        return jsonify(error=msg or "Não foi possível criar usuários"), 400

    host = ""
    try:
        hosts = dbq.effective_dashboard_proxy_hostnames_for_user(user)
        if hosts:
            host = str(hosts[0] or "").strip().lower()
    except Exception:
        host = ""
    if not host:
        host = "proxy.cpaproxys.shop"

    gw = int(user.get("porta") or porta_inf or 0)
    entries_out = []
    for row in created:
        usr = row.get("username")
        pwd = row.get("senha")
        lines = f"{host}:{gw}:{usr}:{pwd}"
        entries_out.append({"username": usr, "senha": pwd, "proxy_line_completa": lines})

    unames = [str(e.get("username") or "") for e in entries_out if e.get("username")]
    preview = ",".join(unames)
    if len(preview) > 420:
        preview = preview[:417] + "..."
    dbq.insert_audit_log(
        user["username"],
        "socio.user.create",
        "user_bulk",
        None,
        f"quantidade={len(entries_out)} limite_gb_cada={limite_gb} porta={porta_inf} usuarios={preview}",
    )

    return jsonify(
        ok=True,
        quantidade=len(entries_out),
        gateway_porta=gw,
        proxy_host_padrao=host,
        entries=entries_out,
        texto_linhas="\n".join(e["proxy_line_completa"] for e in entries_out),
    )


@bp.patch("/me/socio/users/<child_username>/limite_gb")
def socio_patch_limite_gb(child_username: str):
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.users.quota")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    if _socio_me_mutacao_bloqueada_para_dono(rbac, user):
        return jsonify(
            error="Alteração de cota só pode ser feita logado como conta sócio de topo (não pela visualização do dono).",
        ), 403

    child_username = (child_username or "").strip()
    if not child_username:
        return jsonify(error="Usuário inválido"), 400
    if not q.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio podem alterar cotas aqui."), 403
    if not q.filho_pertence_ao_socio(user["username"], child_username):
        return jsonify(error="Usuário não pertence aos seus clientes."), 403

    body = request.get_json(silent=True) or {}
    try:
        gb = float(body.get("limite_gb"))
    except (TypeError, ValueError):
        return jsonify(error="limite_gb inválido"), 400

    child_row = q.get_users(child_username)
    old_gb = float(child_row.get("limite_gb") or 0) if child_row else 0.0

    ok, uerr = q.update_user_limite_gb(child_username, gb)
    if not ok:
        return jsonify(error=uerr or "Não foi possível atualizar"), 400
    q.insert_audit_log(
        user["username"],
        "socio.user.quota",
        "user",
        child_username,
        f"limite_gb {old_gb} -> {gb}",
    )
    return jsonify(ok=True)


@bp.get("/me/socio/users/<child_username>/logs")
def socio_child_logs(child_username: str):
    from cpa_panel.db.queries import (
        ME_LOGS_CAP,
        ME_LOGS_PAGE_SIZE,
        count_proxy_logs_capped,
        list_proxy_logs_paginated,
    )
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm
    from cpa_panel.services.date_range import normalize_day_range

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.users.logs")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            error="Para o dono do painel, informe qual sócio: parâmetro de consulta socio=username (mesmo da lista em «Meus clientes»).",
        ), 400

    effective = str(ctx["effective"] or "").strip()
    child_username = (child_username or "").strip()
    if not child_username:
        return jsonify(error="Usuário inválido"), 400
    if not q.filho_pertence_ao_socio(effective, child_username):
        return jsonify(error="Usuário não pertence aos seus clientes."), 403

    raw_page = request.args.get("page", "0")
    try:
        page = int(raw_page)
    except ValueError:
        page = 0

    df = request.args.get("date_from") or request.args.get("from")
    dt = request.args.get("date_to") or request.args.get("to")
    ca, cb = normalize_day_range(df, dt)

    rows = list_proxy_logs_paginated(
        child_username,
        page=page,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total_in_window = count_proxy_logs_capped(
        child_username,
        created_after=ca,
        created_before_exclusive=cb,
    )
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)

    return jsonify(
        logs=out,
        username=child_username,
        page=page,
        page_size=ME_LOGS_PAGE_SIZE,
        max_logs=ME_LOGS_CAP,
        total_in_window=total_in_window,
    )


@bp.get("/me/socio/audit-logs")
def socio_audit_logs():
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    if not has_perm(rbac, "socio.relatorio") and not has_perm(rbac, "socio.panel"):
        return jsonify(error="Sem permissão para consultar o registro de atividades do sócio."), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            pick_socio=True,
            socios=ctx.get("socios") or [],
            logs=[],
            page=0,
            limit=50,
            total=0,
            read_only_view_as=True,
        )

    effective = str(ctx["effective"] or "").strip()

    raw_page = request.args.get("page", "0")
    raw_limit = request.args.get("limit", "50")
    try:
        page = max(0, int(raw_page))
    except ValueError:
        page = 0
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 50
    offset = page * limit

    df = request.args.get("date_from") or request.args.get("from")
    dt = request.args.get("date_to") or request.args.get("to")
    ca, cb = normalize_day_range(df, dt)

    rows = q.list_audit_logs_for_actor(
        effective,
        limit=limit,
        offset=offset,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total = q.count_audit_logs_for_actor(effective, created_after=ca, created_before_exclusive=cb)

    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)
    return jsonify(
        pick_socio=False,
        read_only_view_as=bool(ctx.get("read_only_view_as")),
        logs=out,
        page=page,
        limit=limit,
        total=total,
    )


@bp.get("/me/socio/recarga-pedidos")
def socio_recarga_pedidos_list():
    """Pedidos PIX de recarga da rede do sócio (ele + clientes criados por ele)."""
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.relatorio")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            pick_socio=True,
            socios=ctx.get("socios") or [],
            pedidos=[],
            page=0,
            limit=40,
            total=0,
            read_only_view_as=True,
        )

    effective = str(ctx["effective"] or "").strip()

    raw_page = request.args.get("page", "0")
    raw_limit = request.args.get("limit", "40")
    try:
        page = max(0, int(raw_page))
    except ValueError:
        page = 0
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 40
    offset = page * limit

    df = request.args.get("date_from") or request.args.get("from")
    dt = request.args.get("date_to") or request.args.get("to")
    ca, cb = normalize_day_range(df, dt)

    rows = q.list_recarga_pedidos_pix_for_socio_network(
        effective,
        limit=limit,
        offset=offset,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total = q.count_recarga_pedidos_pix_for_socio_network(
        effective,
        created_after=ca,
        created_before_exclusive=cb,
    )
    out = [_serialize_pedido_row(dict(r)) for r in rows or []]
    return jsonify(
        pick_socio=False,
        read_only_view_as=bool(ctx.get("read_only_view_as")),
        pedidos=out,
        page=page,
        limit=limit,
        total=total,
    )


_POOL_AVISO_EVENTS = frozenset({"pix_cobranca_pool_excedido", "pix_finalize_pool_blocked"})


@bp.get("/me/socio/recarga-avisos")
def socio_recarga_avisos():
    """Tentativas de recarga PIX bloqueadas por falta de GB no pool (clientes do sócio)."""
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.panel")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            pick_socio=True,
            socios=ctx.get("socios") or [],
            avisos=[],
            read_only_view_as=True,
        )

    effective = str(ctx["effective"] or "").strip()

    raw_limit = request.args.get("limit", "80")
    try:
        lim = max(1, min(int(raw_limit), 200))
    except ValueError:
        lim = 80

    rows = q.list_recarga_payment_logs_for_criados_por(effective, lim * 3)
    out = []
    for r in rows:
        et = str(r.get("event_type") or "")
        if et not in _POOL_AVISO_EVENTS:
            continue
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)
        if len(out) >= lim:
            break

    return jsonify(
        pick_socio=False,
        read_only_view_as=bool(ctx.get("read_only_view_as")),
        avisos=out,
    )


@bp.get("/me/socio/proxy-hosts")
def socio_proxy_hosts_list():
    """Pedidos de hosts de proxy do sócio (pendente / aprovado / rejeitado). Dono: ?socio=."""
    from cpa_panel.db import queries as q
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.panel")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    ctx = _resolve_effective_socio_me_routes(request, user, rbac)
    if ctx.get("http_error"):
        msg, code = ctx["http_error"]
        return jsonify(error=msg), code
    if ctx.get("pick_socio"):
        return jsonify(
            pick_socio=True,
            socios=ctx.get("socios") or [],
            entries=[],
            read_only_view_as=True,
        )

    effective = str(ctx["effective"] or "").strip()
    rows = q.list_socio_proxy_host_rows(effective)
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        item["updated_at"] = _serialize_ts(item.get("updated_at"))
        item["reviewed_at"] = _serialize_ts(item.get("reviewed_at"))
        out.append(item)
    return jsonify(
        pick_socio=False,
        read_only_view_as=bool(ctx.get("read_only_view_as")),
        entries=out,
    )


@bp.post("/me/socio/proxy-hosts")
def socio_proxy_hosts_propose():
    """Propõe um hostname/IP para o painel do sócio e clientes; dono aprova no ARE CEO."""
    from cpa_panel.db import queries as q
    from cpa_panel.services.dashboard_hosts_normalize import normalize_dashboard_host_value
    from cpa_panel.services.rbac_service import compute_rbac, require_perm

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return jsonify(error=str(e)), 401
    except PermissionError as e:
        return jsonify(error=str(e)), 401

    rbac = compute_rbac(user)
    try:
        require_perm(rbac, "socio.panel")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    if _socio_me_mutacao_bloqueada_para_dono(rbac, user):
        return jsonify(
            error="Cadastro de hosts só pode ser feito logado como conta sócio de topo (não pela visualização do dono).",
        ), 403
    if not q.usuario_e_socio_responsavel(user["username"]):
        return jsonify(error="Apenas contas sócio de topo podem solicitar hosts aqui."), 403

    body = request.get_json(silent=True) or {}
    raw = body.get("hostname", body.get("host"))
    try:
        hn = normalize_dashboard_host_value(str(raw or ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400

    ok, err, row = q.propose_socio_proxy_host(user["username"], hn)
    if not ok:
        return jsonify(error=err or "Não foi possível registrar o host"), 400

    q.insert_audit_log(
        user["username"],
        "socio.proxy_host.propose",
        "socio_proxy_host",
        str(row.get("id")) if row else None,
        f"hostname={hn!r}",
    )
    item = dict(row) if row else {}
    item["created_at"] = _serialize_ts(item.get("created_at"))
    item["updated_at"] = _serialize_ts(item.get("updated_at"))
    item["reviewed_at"] = _serialize_ts(item.get("reviewed_at"))
    return jsonify(ok=True, entry=item)
