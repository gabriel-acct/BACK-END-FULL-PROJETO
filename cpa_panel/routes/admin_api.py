from __future__ import annotations

import re
from decimal import Decimal
import secrets
import string

from flask import Blueprint, jsonify, request

from cpa_panel.db import queries
from cpa_panel.gateway_ports import is_allowed_port
from cpa_panel.routes.api import _serialize_ts, _user_from_bearer
from cpa_panel.security import (
    CeoUnlockInvalidError,
    TokenInvalidError,
    issue_ceo_unlock_token,
    issue_impersonation_token,
    payload_from_authorization_header,
    payload_from_ceo_unlock_token,
)
from cpa_panel.services.dashboard_hosts_normalize import normalize_dashboard_host_value
from cpa_panel.services.date_range import normalize_day_range
from cpa_panel.services.rbac_service import compute_rbac, has_admin_area_access, has_perm, require_perm
from cpa_panel.services.ceo_pin_service import body_has_valid_ceo_pin
from cpa_panel.services.private_admin_bridge import ctx_from_private_admin_token


def _can_view_payment_logs(rbac: dict) -> bool:
    if rbac.get("bypass_all"):
        return True
    return (
        has_perm(rbac, "logs.full")
        or has_perm(rbac, "recarga.manage")
        or has_perm(rbac, "logs.payments")
    )

bp = Blueprint("cpa_admin_api", __name__, url_prefix="/api/admin")

_CEO_UNLOCK_EXEMPT_ENDPOINTS = frozenset(
    {
        "cpa_admin_api.dono_ceo_unlock",
        "cpa_admin_api.dono_ceo_session",
    },
)


def _ceo_unlock_subject(token_payload: dict | None, user: dict) -> str:
    """Chave estável para o token de desbloqueio (evita mismatch admin Private × CPA)."""
    if token_payload and token_payload.get("role") == "admin":
        try:
            admin_id = int(token_payload.get("sub") or 0)
        except (TypeError, ValueError):
            admin_id = 0
        if admin_id > 0:
            return f"admin:{admin_id}"
    return str(user.get("username") or "")


@bp.before_request
def _guard_dono_ceo_unlock():
    """Conta Dono (bypass_all): toda rota /api/admin exige token de desbloqueio válido (20 min)."""
    if request.method == "OPTIONS":
        return None
    ep = request.endpoint or ""
    if ep in _CEO_UNLOCK_EXEMPT_ENDPOINTS:
        return None
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    if not rbac.get("bypass_all"):
        return None
    raw_unlock = (request.headers.get("X-Ceo-Unlock") or "").strip()
    if not raw_unlock:
        return (
            jsonify(
                error="Área do Dono bloqueada. Informe a senha ARE CEO para continuar.",
                code="ceo_unlock_required",
            ),
            403,
        )
    try:
        token_payload = _jwt_payload_from_request()
    except TokenInvalidError as e:
        return jsonify(error=str(e), code="ceo_unlock_invalid"), 403
    try:
        payload = payload_from_ceo_unlock_token(raw_unlock)
    except CeoUnlockInvalidError as e:
        return jsonify(error=str(e), code="ceo_unlock_invalid"), 403
    expected_sub = _ceo_unlock_subject(token_payload, user)
    if str(payload.get("sub") or "") != expected_sub:
        return jsonify(error="Sessão ARE CEO inválida", code="ceo_unlock_invalid"), 403
    return None

_SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{1,62}$")
_USER_PREFIX_SAFE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
# Hostname simples (ASCII), ex.: sub.example.com — só para hosts bloqueados (domínio).
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$"
)


def _normalize_domain(raw: str) -> str:
    t = (raw or "").strip().lower().rstrip(".")
    if not t or len(t) > 253:
        raise ValueError("domínio inválido")
    if not _DOMAIN_RE.match(t):
        raise ValueError("domínio inválido (use apenas letras, números, pontos e hífen)")
    return t


def _require_dono(rbac: dict):
    if rbac.get("bypass_all"):
        return None
    return jsonify(error="Apenas o dono pode usar esta função"), 403

_BATCH_USERS_MAX = 200
_BATCH_ALNUM = string.ascii_lowercase + string.digits


def _rand_password_site() -> str:
    raw = secrets.token_urlsafe(12)
    if len(raw) < 12:
        return raw + secrets.token_hex(8)
    return raw


def _rand_username_bulk() -> str:
    return "".join(secrets.choice(_BATCH_ALNUM) for _ in range(10))


def _unique_username_random() -> str | None:
    for _ in range(80):
        u = _rand_username_bulk()
        if not queries.username_exists(u):
            return u
    return None


def _jwt_payload_from_request() -> dict:
    """Aceita JWT CPA (usuarios_proxy) ou JWT do painel admin (painel_admin_users / JWT_SECRET)."""
    auth = request.headers.get("Authorization")
    try:
        return payload_from_authorization_header(auth)
    except TokenInvalidError:
        pass
    from app.service.segury import TokenInvalidError as PrivateTokenInvalidError
    from app.service.segury import payload_from_authorization_header as private_payload_from_auth

    try:
        return private_payload_from_auth(auth)
    except PrivateTokenInvalidError as e:
        raise TokenInvalidError(str(e)) from e


def _ctx():
    try:
        token_payload = _jwt_payload_from_request()
    except TokenInvalidError as e:
        return None, (jsonify(error=str(e)), 401)
    if token_payload.get("imp"):
        return None, (
            jsonify(
                error="Sessão de personificação ativa. Volte ao seu usuário no painel antes de usar a administração.",
            ),
            403,
        )

    if token_payload.get("role") == "admin":
        bridged, err = ctx_from_private_admin_token(token_payload)
        if err:
            return None, err
        if bridged:
            return bridged, None

    try:
        user = _user_from_bearer()
    except TokenInvalidError as e:
        return None, (jsonify(error=str(e)), 401)
    except PermissionError as e:
        return None, (jsonify(error=str(e)), 401)
    rbac = compute_rbac(user)
    if not has_admin_area_access(rbac):
        return None, (jsonify(error="Acesso administrativo negado"), 403)
    return (user, rbac), None


def _audit(actor: str, action: str, target_type: str | None, target_key: str | None, detail: str | None = None):
    queries.insert_audit_log(actor, action, target_type, target_key, detail)


def _created_bounds_from_request():
    """Lê ?date_from=&date_to= (YYYY-MM-DD); também aceita from/to."""
    df = request.args.get("date_from") or request.args.get("from")
    dt = request.args.get("date_to") or request.args.get("to")
    return normalize_day_range(df, dt)


def _reject_if_ceo_pin_invalid(body: dict | None):
    """Retorna (jsonify, 400) se o PIN ARE CEO for inválido; senão None."""
    if body_has_valid_ceo_pin(body if isinstance(body, dict) else None):
        return None
    return jsonify(error="Senha ARE CEO incorreta ou ausente (campo ceo_pin)."), 400


@bp.post("/dono/ceo-unlock")
def dono_ceo_unlock():
    """Desbloqueia a página ARE CEO por 20 min (valida ceo_pin; devolve token opaco)."""
    try:
        c, err = _ctx()
        if err:
            return err
        user, rbac = c
        deny = _require_dono(rbac)
        if deny:
            return deny
        body = request.get_json(silent=True) or {}
        pin_rej = _reject_if_ceo_pin_invalid(body)
        if pin_rej is not None:
            return pin_rej
        try:
            token_payload = _jwt_payload_from_request()
        except TokenInvalidError:
            token_payload = {}
        subject = _ceo_unlock_subject(token_payload, user)
        tok, exp = issue_ceo_unlock_token(subject)
        exp_iso = exp.isoformat().replace("+00:00", "Z")
        return jsonify(ok=True, ceo_unlock_token=tok, expires_at=exp_iso)
    except Exception as e:
        from flask import current_app

        current_app.logger.exception("dono_ceo_unlock falhou")
        detail = str(e) if current_app.debug else None
        payload: dict = {"error": "Não foi possível desbloquear a área ARE CEO"}
        if detail:
            payload["detail"] = detail[:500]
        return jsonify(payload), 500


@bp.get("/dono/ceo-session")
def dono_ceo_session():
    """Verifica se o token de desbloqueio ARE CEO ainda é válido."""
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    raw_unlock = (request.headers.get("X-Ceo-Unlock") or "").strip()
    if not raw_unlock:
        return jsonify(ok=False, error="Sessão inexistente"), 401
    try:
        token_payload = _jwt_payload_from_request()
    except TokenInvalidError:
        token_payload = {}
    try:
        payload = payload_from_ceo_unlock_token(raw_unlock)
    except CeoUnlockInvalidError as e:
        return jsonify(ok=False, error=str(e)), 401
    expected_sub = _ceo_unlock_subject(token_payload, user)
    if str(payload.get("sub") or "") != expected_sub:
        return jsonify(ok=False, error="Sessão inválida"), 401
    exp_ts = int(payload.get("exp") or 0)
    return jsonify(ok=True, expires_at=exp_ts)


@bp.get("/summary")
def summary():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    ca, cb = _created_bounds_from_request()
    out = {
        "you": user["username"],
        "proxy_logs_total": 0,
        "audit_logs_total": 0,
        "users_total": 0,
        "payment_logs_total": 0,
    }
    if has_perm(rbac, "logs.full") or rbac.get("bypass_all"):
        out["proxy_logs_total"] = queries.count_proxy_logs_all(
            created_after=ca,
            created_before_exclusive=cb,
        )
    if _can_view_payment_logs(rbac):
        out["payment_logs_total"] = queries.count_recarga_payment_logs_all(
            created_after=ca,
            created_before_exclusive=cb,
        )
    if rbac.get("bypass_all"):
        out["audit_logs_total"] = queries.count_audit_logs(
            created_after=ca,
            created_before_exclusive=cb,
        )
        out["ceo_valor_extra_reais"] = round(queries.get_ceo_valor_extra_reais(), 8)
    if has_perm(rbac, "users.view") or rbac.get("bypass_all"):
        rows = queries.list_users_admin(created_after=ca, created_before_exclusive=cb)
        out["users_total"] = len(rows)
    return jsonify(out)


@bp.get("/dono/relatorio-contas")
def dono_relatorio_contas():
    """Contagem de contas proxy criadas (por período e por dia); exclusivo bypass / dono."""
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    ca, cb = _created_bounds_from_request()
    filtros_em_uso = ca is not None or cb is not None
    total_linhas = queries.count_usuarios_proxy_rows()
    no_filtro = queries.count_usuarios_proxy_by_created_bounds(ca, cb)
    sem_dt = queries.count_usuarios_proxy_sem_criado_em()
    if no_filtro is None:
        return (
            jsonify(
                error="Não foi possível ler a data de criação na tabela usuarios_proxy "
                "(esperado: coluna criado_em ou created_at).",
            ),
            503,
        )
    dia_rows = queries.list_usuario_creation_counts_by_day(ca, cb)
    por_dia = [{"dia": item["day"], "quantidade": item["count"]} for item in dia_rows]

    gb_geral = queries.aggregate_usuarios_proxy_gb(None, None)
    gb_intervalo = queries.aggregate_usuarios_proxy_gb(ca, cb) if filtros_em_uso else gb_geral
    if gb_geral is None or gb_intervalo is None:
        return (
            jsonify(
                error="Não foi possível agregar GB na tabela usuarios_proxy (data de criação ou colunas).",
            ),
            503,
        )

    linhas_gb = (
        queries.list_usuarios_proxy_gb_linhas(ca, cb) if filtros_em_uso else queries.list_usuarios_proxy_gb_linhas(None, None)
    )
    if linhas_gb is None:
        linhas_gb = []

    def _gb_resumo_block(agg: dict) -> dict:
        ub = int(agg.get("soma_usado_bytes") or 0)
        return {
            "contas": int(agg.get("contas") or 0),
            "soma_limite_gb": round(float(agg.get("soma_limite_gb") or 0), 6),
            "soma_gb_trafego_usado": round(ub / (1000**3), 6),
        }

    usuarios_gb = []
    for r in linhas_gb:
        ub = int(r.get("usado_bytes") or 0)
        usuarios_gb.append(
            {
                "username": str(r.get("username") or ""),
                "limite_gb": round(float(r.get("limite_gb") or 0), 6),
                "gb_trafego_usado": round(ub / (1000**3), 6),
            }
        )

    ranking = queries.audit_ranking_user_creates(ca, cb, limit=80)
    eventos_rows = queries.list_audit_user_create_events(ca, cb, limit=350)
    auditoria_criacoes = []
    for ev in eventos_rows or []:
        auditoria_criacoes.append(
            {
                "id": int(ev["id"]),
                "em": _serialize_ts(ev.get("created_at")),
                "ator": str(ev.get("actor_username") or ""),
                "usuario_criado": str(ev.get("target_key") or ""),
                "detalhe": ev.get("detail"),
                "bulk": ";bulk=1" in str(ev.get("detail") or ""),
            }
        )

    _audit(
        user["username"],
        "owner.report.accounts",
        None,
        None,
        ("periodo=" + ("1" if filtros_em_uso else "0")),
    )

    ajuda = (
        "Contagens da tabela usam a coluna criado_em quando existir, senão created_at (legado). "
        "«Quem criou mais» vem do log de auditoria (ação user.create) sempre que admins criam conta pelo painel "
        "(inclui lote quando auditado). "
        "GB: soma_limite_gb é a soma do limite (capacidade) por conta; soma_gb_trafego_usado soma o consumo "
        "(usado_bytes → GB com 1 GB = 10⁹ bytes). Com filtro de datas, só entram contas cuja data de criação cai no intervalo."
    )

    return jsonify(
        {
            "total_contas_na_tabela": total_linhas,
            "no_intervalo_do_filtro": no_filtro,
            "filtro_de_periodo_ativo": filtros_em_uso,
            "contas_sem_criado_em": sem_dt,
            "tem_coluna_data_criacao": sem_dt is not None,
            "contas_sem_created_at": sem_dt,
            "coluna_created_at_disponivel": sem_dt is not None,
            "por_dia": por_dia,
            "quem_criou_mais": ranking,
            "auditoria_criacoes": auditoria_criacoes,
            "gb_resumo_geral": _gb_resumo_block(gb_geral),
            "gb_resumo_intervalo": _gb_resumo_block(gb_intervalo),
            "usuarios_gb": usuarios_gb,
            "ajuda": ajuda,
        }
    )


@bp.get("/dono/dashboard-proxy-hosts")
def dono_dashboard_proxy_hosts_get():
    """Lista de hosts exibidos no dashboard do cliente (ordem = ordem dos botões). Somente dono (bypass_all)."""
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    hosts = queries.list_dashboard_proxy_hostnames()
    return jsonify(hosts=hosts)


@bp.put("/dono/dashboard-proxy-hosts")
def dono_dashboard_proxy_hosts_put():
    """Substitui a lista de hosts do dashboard. Body: {\"hosts\": [\"a.com\", \"1.2.3.4\", ...]}. Somente dono."""
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    body = request.get_json(silent=True) or {}
    raw_hosts = body.get("hosts")
    if not isinstance(raw_hosts, list):
        return jsonify(error='Informe "hosts" como array de strings'), 400
    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_hosts:
        try:
            n = normalize_dashboard_host_value(str(item))
        except ValueError as e:
            return jsonify(error=str(e)), 400
        if n not in seen:
            seen.add(n)
            normalized.append(n)
    ok, err_msg = queries.replace_dashboard_proxy_hostnames(normalized)
    if not ok:
        return jsonify(error=err_msg or "Falha ao salvar hosts"), 500
    _audit(
        str(user["username"]),
        "owner.dashboard_proxy_hosts.set",
        "settings",
        "dashboard_proxy_hosts",
        f"count={len(normalized)}",
    )
    return jsonify(hosts=queries.list_dashboard_proxy_hostnames())


@bp.get("/dono/socio-overview")
def dono_socio_overview():
    """Visão consolidada de todos os sócios de topo: pool, PushinPay próprio, marca. Somente dono (ARE CEO)."""
    c, err = _ctx()
    if err:
        return err
    _user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    rows = queries.list_socio_responsavel_overview_rows()
    socios: list[dict] = []
    for r in rows:
        o = dict(r)
        sp = queries.get_socio_pushinpay(str(o.get("username") or ""))
        t = (sp.get("api_token") or "").strip() if sp else ""
        o["pushinpay_token_preview"] = _mask_secret_preview(t) if t else None
        o["pushinpay_webhook_secret_ok"] = bool(sp and (sp.get("webhook_secret") or "").strip())
        socios.append(o)
    return jsonify(socios=socios)


@bp.get("/dono/socio-proxy-hosts")
def dono_socio_proxy_hosts_list():
    """Pedidos de hosts por sócio (pendente / aprovado / rejeitado). Somente dono (bypass_all)."""
    c, err = _ctx()
    if err:
        return err
    _user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    raw_status = (request.args.get("status") or "").strip().lower()
    status = raw_status if raw_status in ("pending", "approved", "rejected") else None
    socio_f = (request.args.get("socio") or "").strip() or None
    rows = queries.list_socio_proxy_hosts_for_dono(status=status, socio_username=socio_f)
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        item["updated_at"] = _serialize_ts(item.get("updated_at"))
        item["reviewed_at"] = _serialize_ts(item.get("reviewed_at"))
        out.append(item)
    return jsonify(entries=out)


@bp.patch("/dono/socio-proxy-hosts/<int:entry_id>")
def dono_socio_proxy_hosts_patch(entry_id: int):
    """Aprovar ou rejeitar um host sugerido por sócio. Body: {\"status\": \"approved\"|\"rejected\"}."""
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    body = request.get_json(silent=True) or {}
    st = str(body.get("status") or "").strip().lower()
    if st not in ("approved", "rejected"):
        return jsonify(error='Informe "status": "approved" ou "rejected"'), 400
    ok, uerr, row = queries.dono_set_socio_proxy_host_status(entry_id, st, str(user.get("username") or ""))
    if not ok:
        return jsonify(error=uerr or "Falha ao atualizar"), 400
    socio_u = str((row or {}).get("socio_username") or "")
    hn = str((row or {}).get("hostname") or "")
    _audit(
        str(user["username"]),
        f"owner.socio_proxy_host.{st}",
        "socio_proxy_host",
        str(entry_id),
        f"socio={socio_u!r} hostname={hn!r}",
    )
    if row:
        item = dict(row)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        item["updated_at"] = _serialize_ts(item.get("updated_at"))
        item["reviewed_at"] = _serialize_ts(item.get("reviewed_at"))
        return jsonify(entry=item)
    return jsonify(ok=True)


@bp.get("/users")
def list_users():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    try:
        require_perm(rbac, "users.view")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    ca, cb = _created_bounds_from_request()
    rows = queries.list_users_admin(created_after=ca, created_before_exclusive=cb)
    for r in rows:
        r["limite_gb"] = float(r["limite_gb"] or 0)
        u = int(r.get("usado_bytes") or 0)
        r["usado_bytes"] = u
        r["mb_usados"] = round(u / (1000**2), 4)
        r["gb_usados"] = round(u / (1000**3), 6)
        r.setdefault("custo_pago", 0)
        r["custo_pago"] = 1 if int(r.get("custo_pago") or 0) else 0
        raw_baseline = r.get("ceo_limite_gb_basico")
        if raw_baseline is None or raw_baseline == "":
            r["ceo_limite_gb_basico"] = None
        else:
            try:
                r["ceo_limite_gb_basico"] = float(raw_baseline)
            except (TypeError, ValueError):
                r["ceo_limite_gb_basico"] = None
        raw_ts = r.get("criado_em") or r.get("created_at")
        if raw_ts is not None:
            iso = _serialize_ts(raw_ts)
            r["criado_em"] = iso
            r["created_at"] = iso
        else:
            r["criado_em"] = None
            r["created_at"] = None
    return jsonify(users=rows)


@bp.post("/impersonate")
def impersonate_start():
    """JWT do usuário alvo para ver o painel como ele. Apenas dono; alvos com bypass total são bloqueados."""
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    err_resp = _require_dono(rbac)
    if err_resp is not None:
        return err_resp
    body = request.get_json(silent=True) or {}
    target_username = str(body.get("username", "")).strip()
    if not target_username:
        return jsonify(error="username obrigatório"), 400
    if target_username == actor["username"]:
        return jsonify(error="Para sua conta use o login habitual"), 400
    target = queries.get_user_for_auth(target_username) or queries.get_users(target_username)
    if not target:
        return jsonify(error="Usuário não encontrado"), 404
    if int(target.get("cargo_bypass_all") or 0) == 1:
        return jsonify(error="Não é permitido personificar conta com cargo Dono"), 403
    try:
        porta = int(target.get("porta") or 0)
    except (TypeError, ValueError):
        return jsonify(error="Porta inválida no cadastro do usuário"), 400
    if porta <= 0:
        return jsonify(error="Usuário sem porta válida"), 400

    tok = issue_impersonation_token(str(target["username"]), porta, str(actor["username"]))
    _audit(str(actor["username"]), "user.impersonate.start", "user", target_username, None)
    return jsonify(access_token=tok, token_type="bearer")


@bp.post("/users")
def create_user():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "users.create")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    senha = str(body.get("senha", ""))
    try:
        porta = int(body.get("porta", 823))
    except (TypeError, ValueError):
        return jsonify(error="porta inválida"), 400

    if not is_allowed_port(porta):
        return jsonify(error="Porta deve ser 823 (HTTP) ou 824 (SOCKS5)"), 400
    try:
        limite_gb = float(body.get("limite_gb", 0))
    except (TypeError, ValueError):
        return jsonify(error="limite_gb inválido"), 400

    raw_cargo = body.get("cargo_id")
    cargo_id = None
    if raw_cargo is not None and raw_cargo != "":
        if not rbac.get("bypass_all"):
            return jsonify(error="Apenas o dono pode definir cargo ao criar usuário"), 403
        try:
            cargo_id = int(raw_cargo)
        except (TypeError, ValueError):
            return jsonify(error="cargo_id inválido"), 400
        cargo = queries.get_cargo_by_id(cargo_id)
        if not cargo:
            return jsonify(error="Cargo não encontrado"), 404
        if int(cargo.get("bypass_all") or 0) == 1 and not rbac.get("bypass_all"):
            return jsonify(error="Apenas o dono pode criar conta com cargo Dono"), 403

    ok, msg = queries.create_usuario_proxy(username, senha, porta, limite_gb, cargo_id)
    if not ok:
        return jsonify(error=msg or "Não foi possível criar usuário"), 400
    _audit(actor["username"], "user.create", "user", username, f"porta={porta};limite_gb={limite_gb}")
    return jsonify(ok=True, username=username)


@bp.post("/users/bulk")
def create_users_bulk():
    """
    Cria vários usuários proxy usando a mesma porta em todas as contas.
    Devolve linhas para copiar no formato host:porta:usuario:senha (credenciais em texto por necessidade administrativa).
    """
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "users.create")
    except PermissionError as e:
        return jsonify(error=str(e)), 403

    body = request.get_json(silent=True) or {}
    raw_count = body.get("quantidade", body.get("count"))
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        return jsonify(error="quantidade inválida"), 400
    if count < 1 or count > _BATCH_USERS_MAX:
        return jsonify(error=f"quantidade deve ser entre 1 e {_BATCH_USERS_MAX}"), 400

    try:
        porta_padrao = int(body.get("porta", body.get("porta_inicial", 823)))
    except (TypeError, ValueError):
        return jsonify(error="porta inválida"), 400
    if not is_allowed_port(porta_padrao):
        return jsonify(error="Porta deve ser 823 (HTTP) ou 824 (SOCKS5)"), 400
    try:
        limite_gb = float(body.get("limite_gb", 0))
    except (TypeError, ValueError):
        return jsonify(error="limite_gb inválido"), 400

    random_credentials = bool(body.get("credenciais_aleatorias", body.get("random_credentials")))
    proxy_host = str(body.get("proxy_host", "") or "proxy.cpaproxys.shop").strip().lower().rstrip(".")
    if not proxy_host or len(proxy_host) > 253:
        return jsonify(error="proxy_host inválido"), 400

    username_prefix_raw = str(body.get("username_prefix", "cli") or "cli").strip().lower()
    if random_credentials:
        username_prefix_safe = ""
    else:
        if not _USER_PREFIX_SAFE.match(username_prefix_raw):
            return jsonify(
                error="username_prefix inválido (use apenas a-z, números e _, começando com letra, máximo 40 chars)",
            ), 400
        username_prefix_safe = username_prefix_raw

    seq_start = body.get("sequencia_inicio")
    seq_n = 1
    if not random_credentials and seq_start is not None:
        try:
            seq_n = max(1, int(seq_start))
        except (TypeError, ValueError):
            return jsonify(error="sequencia_inicio inválido"), 400

    raw_cargo = body.get("cargo_id")
    cargo_id = None
    if raw_cargo is not None and raw_cargo != "":
        if not rbac.get("bypass_all"):
            return jsonify(error="Apenas o dono pode definir cargo ao criar usuário"), 403
        try:
            cargo_id = int(raw_cargo)
        except (TypeError, ValueError):
            return jsonify(error="cargo_id inválido"), 400
        cargo = queries.get_cargo_by_id(cargo_id)
        if not cargo:
            return jsonify(error="Cargo não encontrado"), 404
        if int(cargo.get("bypass_all") or 0) == 1 and not rbac.get("bypass_all"):
            return jsonify(error="Apenas o dono pode criar conta com cargo Dono"), 403

    created: list[dict] = []
    failures: list[dict] = []
    lines: list[str] = []

    for _i in range(count):
        porta_assigned = porta_padrao
        if random_credentials:
            uname = _unique_username_random()
            if not uname:
                failures.append({"porta": porta_assigned, "error": "Não foi possível gerar username único"})
                continue
            senha = _rand_password_site()
        else:
            picked = False
            uname = None
            for _attempt in range(5000):
                cand = f"{username_prefix_safe}_{seq_n:04d}"
                seq_n += 1
                if len(cand) > 128:
                    failures.append({"porta": porta_assigned, "error": "username excedeu 128 caracteres"})
                    cand = ""
                    break
                if not queries.username_exists(cand):
                    uname = cand
                    picked = True
                    break
            if not picked or not uname:
                if not failures or failures[-1].get("porta") != porta_assigned:
                    failures.append({"porta": porta_assigned, "error": "Esgotou tentativas de username sequencial"})
                continue
            senha = _rand_password_site()

        ok, msg = queries.create_usuario_proxy(uname, senha, porta_assigned, limite_gb, cargo_id)
        if not ok:
            failures.append({"username": uname, "porta": porta_assigned, "error": msg or "create falhou"})
            continue
        line = f"{proxy_host}:{int(porta_assigned)}:{uname}:{senha}"
        lines.append(line)
        created.append({"username": uname, "porta": int(porta_assigned), "senha": senha})
        _audit(actor["username"], "user.create", "user", uname, f"porta={porta_assigned};limite_gb={limite_gb};bulk=1")

    if not lines and failures:
        return jsonify(
            error="Nenhum usuário foi criado",
            failures=failures,
        ), 409

    return jsonify(
        ok=True,
        quantidade_pedida=count,
        criados=len(created),
        linhas=lines,
        contas=created,
        falhas=failures,
        proxy_host=proxy_host,
        porta=porta_padrao,
    )


@bp.patch("/users/<username>/status")
def patch_user_status(username: str):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "users.status")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    try:
        status = int(body.get("status"))
    except (TypeError, ValueError):
        return jsonify(error="status deve ser 0 ou 1"), 400
    if status not in (0, 1):
        return jsonify(error="status deve ser 0 ou 1"), 400
    if status:
        queries.desativar_logs_usuario(username)
    ok = queries.update_user_status(username, status)
    if not ok:
        return jsonify(error="Usuário não encontrado"), 404
    _audit(actor["username"], "user.status", "user", username, f"status={status}")
    return jsonify(ok=True)


@bp.patch("/users/<username>/limite_gb")
def patch_user_limite(username: str):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "users.quota")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    try:
        gb = float(body.get("limite_gb"))
    except (TypeError, ValueError):
        return jsonify(error="limite_gb inválido"), 400
    if gb < 0 or gb > 1_000_000:
        return jsonify(error="limite_gb fora do intervalo permitido"), 400
    ok, uerr = queries.update_user_limite_gb(username, gb)
    if not ok:
        txt = (uerr or "").lower()
        if "não encontrado" in txt:
            return jsonify(error=uerr or "Usuário não encontrado"), 404
        return jsonify(error=uerr or "Não foi possível atualizar limite_gb"), 400
    _audit(actor["username"], "user.quota", "user", username, f"limite_gb={gb}")
    return jsonify(ok=True)


@bp.patch("/users/<username>")
def patch_user_main_fields(username: str):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "users.create")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}

    new_username = body.get("username")
    new_senha = body.get("senha")
    new_porta = body.get("porta")
    if new_username is not None:
        new_username = str(new_username).strip()
    if new_senha is not None:
        new_senha = str(new_senha)

    ok, msg = queries.update_user_admin_fields(
        current_username=username,
        new_username=new_username,
        new_senha=new_senha,
        new_porta=new_porta,
    )
    if not ok:
        txt = (msg or "").lower()
        if "não encontrado" in txt:
            return jsonify(error=msg or "Usuário não encontrado"), 404
        return jsonify(error=msg or "Falha ao atualizar usuário"), 400
    _audit(actor["username"], "user.update", "user", username, "admin edit")
    return jsonify(ok=True)


@bp.patch("/users/<username>/cargo")
def patch_user_cargo(username: str):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    body = request.get_json(silent=True) or {}
    raw = body.get("cargo_id")
    if raw is None:
        return jsonify(error="cargo_id é obrigatório"), 400
    try:
        cargo_id = int(raw)
    except (TypeError, ValueError):
        return jsonify(error="cargo_id inválido"), 400
    cargo = queries.get_cargo_by_id(cargo_id)
    if not cargo:
        return jsonify(error="Cargo não encontrado"), 404
    if int(cargo.get("bypass_all") or 0) == 1 and not rbac.get("bypass_all"):
        return jsonify(error="Apenas o dono pode atribuir o cargo Dono"), 403
    before = queries.get_user_for_auth(username) or queries.get_users(username)
    old_cargo_id = before.get("cargo_id") if before else None
    old_label = "(sem cargo)"
    if old_cargo_id is not None:
        try:
            old_cargo_id_int = int(old_cargo_id)
            oc = queries.get_cargo_by_id(old_cargo_id_int)
            if oc:
                old_label = str(oc.get("slug") or oc.get("nome") or old_cargo_id_int)
            else:
                old_label = f"id={old_cargo_id_int}"
        except (TypeError, ValueError):
            old_label = str(old_cargo_id)
    new_label = str(cargo.get("slug") or cargo.get("nome") or cargo_id)
    ok = queries.set_user_cargo(username, cargo_id)
    if not ok:
        return jsonify(error="Usuário não encontrado"), 404
    detail = f"de={old_label} para={new_label} (cargo_id {old_cargo_id}→{cargo_id})"
    _audit(actor["username"], "user.cargo", "user", username, detail)
    return jsonify(ok=True)


@bp.patch("/users/<username>/custo_pago")
def patch_user_custo_pago(username: str):
    """ARE CEO: custo/GB pago (coluna usuarios_proxy.custo_pago). Apenas dono."""
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    body = request.get_json(silent=True) or {}
    raw = body.get("custo_pago")
    if isinstance(raw, bool):
        val = 1 if raw else 0
    else:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            return jsonify(error='Informe "custo_pago": true ou false (ou 0/1)'), 400
        if val not in (0, 1):
            return jsonify(error="custo_pago deve ser 0 ou 1"), 400
    if val == 1:
        pin_rej = _reject_if_ceo_pin_invalid(body)
        if pin_rej is not None:
            return pin_rej
    ok = queries.update_user_custo_pago(username, val)
    if not ok:
        return jsonify(error="Usuário não encontrado ou coluna custo_pago ausente no banco"), 404
    _audit(str(actor["username"]), "user.custo_pago", "user", username, f"custo_pago={val}")
    return jsonify(ok=True, custo_pago=val)


@bp.patch("/dono/ceo-valor-extra")
def dono_patch_ceo_valor_extra():
    """Dono: define valor em R$ somado ao total ARE CEO (requer ceo_pin)."""
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    body = request.get_json(silent=True) or {}
    pin_rej = _reject_if_ceo_pin_invalid(body)
    if pin_rej is not None:
        return pin_rej
    raw = body.get("valor_extra_reais")
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return jsonify(error="valor_extra_reais inválido"), 400
    ok, terr = queries.set_ceo_valor_extra_reais(v)
    if not ok:
        return jsonify(error=terr or "Não foi possível gravar (confira sql/painel_ceo_settings.sql)"), 500
    _audit(str(actor["username"]), "ceo.valor_extra", "ceo", "1", f"valor_extra_reais={v}")
    return jsonify(ok=True, valor_extra_reais=round(v, 8))


@bp.post("/dono/usuarios-custo-pago/marcar-todas-com-uso")
def dono_marcar_todas_custo_pago_com_uso():
    """Marca custo_pago = 1 em todas as contas com usado_bytes > 0."""
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    body = request.get_json(silent=True) or {}
    pin_rej = _reject_if_ceo_pin_invalid(body)
    if pin_rej is not None:
        return pin_rej
    n, terr = queries.mark_custo_pago_all_usado_bytes_positive()
    if n is None:
        return jsonify(error=terr or "Falha ao atualizar (confira sql/usuarios_proxy_custo_pago.sql)"), 500
    _audit(str(actor["username"]), "user.custo_pago.bulk_uso", "user", "*", f"marcadas={n}")
    return jsonify(ok=True, marcadas=n)


@bp.post("/dono/usuarios-custo-pago/desmarcar-todas")
def dono_desmarcar_todas_custo_pago():
    """Zera custo_pago nas contas onde estava marcado."""
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    n, terr = queries.clear_all_custo_pago()
    if n is None:
        return jsonify(error=terr or "Falha ao atualizar"), 500
    _audit(str(actor["username"]), "user.custo_pago.clear_all", "user", "*", f"desmarcadas={n}")
    return jsonify(ok=True, desmarcadas=n)


@bp.get("/proxy-logs")
def proxy_logs():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    try:
        require_perm(rbac, "logs.full")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    raw_page = request.args.get("page", "0")
    raw_limit = request.args.get("limit", "50")
    uf = request.args.get("username")
    username_filter = str(uf).strip() if uf else None
    try:
        page = max(0, int(raw_page))
    except ValueError:
        page = 0
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 50
    offset = page * limit
    ca, cb = _created_bounds_from_request()
    rows = queries.list_proxy_logs_all(
        limit=limit,
        offset=offset,
        username_filter=username_filter,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total = queries.count_proxy_logs_all(
        username_filter=username_filter,
        created_after=ca,
        created_before_exclusive=cb,
    )
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)
    return jsonify(logs=out, page=page, limit=limit, total=total)


@bp.get("/payment-logs")
def payment_logs():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    if not _can_view_payment_logs(rbac):
        return jsonify(error="Sem permissão para logs de pagamento"), 403
    raw_page = request.args.get("page", "0")
    raw_limit = request.args.get("limit", "50")
    uf = request.args.get("username")
    username_filter = str(uf).strip() if uf else None
    try:
        page = max(0, int(raw_page))
    except ValueError:
        page = 0
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 50
    offset = page * limit
    ca, cb = _created_bounds_from_request()
    rows = queries.list_recarga_payment_logs_all(
        limit=limit,
        offset=offset,
        username_filter=username_filter,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total = queries.count_recarga_payment_logs_all(
        username_filter=username_filter,
        created_after=ca,
        created_before_exclusive=cb,
    )
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        for k, v in list(item.items()):
            if isinstance(v, Decimal):
                item[k] = float(v)
        out.append(item)
    return jsonify(logs=out, page=page, limit=limit, total=total)


@bp.get("/audit-logs")
def audit_logs():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
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
    ca, cb = _created_bounds_from_request()
    rows = queries.list_audit_logs(
        limit=limit,
        offset=offset,
        created_after=ca,
        created_before_exclusive=cb,
    )
    total = queries.count_audit_logs(created_after=ca, created_before_exclusive=cb)
    out = []
    for r in rows:
        item = dict(r)
        item["created_at"] = _serialize_ts(item.get("created_at"))
        out.append(item)
    return jsonify(logs=out, page=page, limit=limit, total=total)


@bp.get("/permissions")
def permission_defs():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    rows = queries.list_all_permission_definitions()
    return jsonify(permissions=rows)


@bp.get("/cargos")
def cargos():
    c, err = _ctx()
    if err:
        return err
    user, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    rows = queries.list_cargos_with_permissions()
    for r in rows:
        r["bypass_all"] = int(r.get("bypass_all") or 0)
    return jsonify(cargos=rows)


@bp.post("/cargos")
def create_cargo():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    body = request.get_json(silent=True) or {}
    slug = str(body.get("slug", "")).strip().lower()
    nome = str(body.get("nome", "")).strip()
    if not nome:
        return jsonify(error="nome é obrigatório"), 400
    if not _SLUG_RE.match(slug):
        return jsonify(error="slug inválido (use a-z, números e _, começando com letra)"), 400
    if slug in ("dono", "cliente"):
        return jsonify(error="slug reservado"), 400
    codes = body.get("permission_codes")
    if not isinstance(codes, list):
        return jsonify(error="permission_codes deve ser uma lista"), 400
    cid = queries.create_cargo(slug, nome, 0)
    if not cid:
        return jsonify(error="Não foi possível criar (slug duplicado?)"), 409
    queries.replace_cargo_permissions(cid, [str(x) for x in codes])
    _audit(actor["username"], "cargo.create", "cargo", str(cid), slug)
    rows = queries.list_cargos_with_permissions()
    return jsonify(ok=True, cargos=rows)


@bp.patch("/cargos/<int:cargo_id>")
def patch_cargo(cargo_id: int):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    row = queries.get_cargo_by_id(cargo_id)
    if not row:
        return jsonify(error="Cargo não encontrado"), 404
    if row["slug"] == "dono":
        return jsonify(error="O cargo Dono não pode ser editado pela API"), 403
    body = request.get_json(silent=True) or {}
    nome = body.get("nome")
    if nome is not None:
        nome = str(nome).strip()
        if nome:
            queries.update_cargo_meta(cargo_id, nome)
    codes = body.get("permission_codes")
    if codes is not None:
        if not isinstance(codes, list):
            return jsonify(error="permission_codes deve ser uma lista"), 400
        if int(row.get("bypass_all") or 0) != 1:
            queries.replace_cargo_permissions(cargo_id, [str(x) for x in codes])
    _audit(actor["username"], "cargo.update", "cargo", str(cargo_id), row["slug"])
    rows = queries.list_cargos_with_permissions()
    return jsonify(ok=True, cargos=rows)


@bp.delete("/cargos/<int:cargo_id>")
def delete_cargo(cargo_id: int):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    deny = _require_dono(rbac)
    if deny:
        return deny
    ok, msg = queries.delete_cargo_if_allowed(cargo_id)
    if not ok:
        return jsonify(error=msg or "Não foi possível remover"), 409
    _audit(actor["username"], "cargo.delete", "cargo", str(cargo_id), None)
    return jsonify(ok=True)


def _parse_discount_create(body: dict) -> tuple[dict | None, str | None]:
    nome = str(body.get("nome", "")).strip()
    gb_raw = body.get("gb_minimo")
    pct_raw = body.get("percentual_desconto")
    fix_raw = body.get("valor_fixo_reais")
    ativo_raw = body.get("ativo")
    ordem_raw = body.get("ordem")

    if gb_raw is None:
        return None, "gb_minimo é obrigatório"
    try:
        gb_min = float(str(gb_raw).replace(",", "."))
    except (TypeError, ValueError):
        return None, "gb_minimo inválido"
    if gb_min <= 0:
        return None, "gb_minimo deve ser maior que zero"

    pct = None
    fix = None
    if pct_raw is not None and str(pct_raw).strip() != "":
        try:
            pct = float(str(pct_raw).replace(",", "."))
        except (TypeError, ValueError):
            return None, "percentual_desconto inválido"
    if fix_raw is not None and str(fix_raw).strip() != "":
        try:
            fix = float(str(fix_raw).replace(",", "."))
        except (TypeError, ValueError):
            return None, "valor_fixo_reais inválido"

    has_pct = pct is not None and pct > 0
    has_fix = fix is not None and fix > 0
    if has_pct and has_fix:
        return None, "Informe apenas percentual OU valor fixo, não ambos"
    if not has_pct and not has_fix:
        return None, "Informe percentual_desconto (>0) ou valor_fixo_reais (>0)"
    if has_pct and pct is not None and pct > 100:
        return None, "percentual_desconto não pode passar de 100"

    try:
        ativo = int(ativo_raw) if ativo_raw is not None else 1
    except (TypeError, ValueError):
        return None, "ativo inválido"
    try:
        ordem = int(ordem_raw) if ordem_raw is not None else 0
    except (TypeError, ValueError):
        return None, "ordem inválido"

    return {
        "nome": nome,
        "gb_minimo": gb_min,
        "percentual_desconto": pct if has_pct else None,
        "valor_fixo_reais": fix if has_fix else None,
        "ativo": 1 if ativo else 0,
        "ordem": ordem,
    }, None


def _parse_discount_patch(body: dict) -> tuple[dict | None, str | None]:
    nome = str(body.get("nome", "")).strip()
    gb_raw = body.get("gb_minimo")
    pct_raw = body.get("percentual_desconto")
    fix_raw = body.get("valor_fixo_reais")
    ativo_raw = body.get("ativo")
    ordem_raw = body.get("ordem")

    out: dict = {}
    if "nome" in body:
        out["nome"] = nome
    if "gb_minimo" in body and gb_raw is not None:
        try:
            gb_min = float(str(gb_raw).replace(",", "."))
        except (TypeError, ValueError):
            return None, "gb_minimo inválido"
        if gb_min <= 0:
            return None, "gb_minimo deve ser maior que zero"
        out["gb_minimo"] = gb_min

    has_pct_key = "percentual_desconto" in body
    has_fix_key = "valor_fixo_reais" in body
    if has_pct_key:
        if pct_raw is None or str(pct_raw).strip() == "":
            out["percentual_desconto"] = None
        else:
            try:
                p = float(str(pct_raw).replace(",", "."))
            except (TypeError, ValueError):
                return None, "percentual_desconto inválido"
            if p > 100:
                return None, "percentual_desconto não pode passar de 100"
            out["percentual_desconto"] = p if p > 0 else None
    if has_fix_key:
        if fix_raw is None or str(fix_raw).strip() == "":
            out["valor_fixo_reais"] = None
        else:
            try:
                f = float(str(fix_raw).replace(",", "."))
            except (TypeError, ValueError):
                return None, "valor_fixo_reais inválido"
            out["valor_fixo_reais"] = f if f > 0 else None

    if has_pct_key and has_fix_key:
        hp = out.get("percentual_desconto") is not None and (
            out["percentual_desconto"] is not None and float(out["percentual_desconto"]) > 0
        )
        hf = out.get("valor_fixo_reais") is not None and (
            out["valor_fixo_reais"] is not None and float(out["valor_fixo_reais"]) > 0
        )
        if hp and hf:
            return None, "Use apenas percentual OU valor fixo"

    if "ativo" in body and ativo_raw is not None:
        try:
            out["ativo"] = 1 if int(ativo_raw) else 0
        except (TypeError, ValueError):
            return None, "ativo inválido"
    if "ordem" in body and ordem_raw is not None:
        try:
            out["ordem"] = int(ordem_raw)
        except (TypeError, ValueError):
            return None, "ordem inválido"

    if not out:
        return None, "Nenhum campo para atualizar"
    return out, None


def _discount_patch_merge_ok(row: dict, patch: dict) -> tuple[bool, str | None]:
    tmp = dict(row)
    tmp.update(patch)

    def gf(key):
        v = tmp.get(key)
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    pct_f = gf("percentual_desconto")
    fix_f = gf("valor_fixo_reais")
    has_p = pct_f is not None and pct_f > 0
    has_f = fix_f is not None and fix_f > 0
    if has_p and has_f:
        return False, "Percentual e valor fixo não podem ficar ativos ao mesmo tempo"
    if not has_p and not has_f:
        return False, "É obrigatório ter percentual_desconto ou valor_fixo_reais maior que zero"
    return True, None


def _serialize_discount_admin(row):
    r = dict(row)
    pct = r.get("percentual_desconto")
    fix = r.get("valor_fixo_reais")
    item = {
        "id": int(r["id"]),
        "nome": r.get("nome") or "",
        "gb_minimo": float(r["gb_minimo"]),
        "percentual_desconto": float(pct) if pct is not None else None,
        "valor_fixo_reais": float(fix) if fix is not None else None,
        "ativo": int(r.get("ativo", 1)),
        "ordem": int(r.get("ordem", 0)),
    }
    if r.get("created_at"):
        item["created_at"] = _serialize_ts(r["created_at"])
    if r.get("updated_at"):
        item["updated_at"] = _serialize_ts(r["updated_at"])
    return item


@bp.get("/recarga/descontos")
def list_recarga_descontos():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    rows = queries.list_recarga_descontos_admin()
    return jsonify(descontos=[_serialize_discount_admin(r) for r in rows])


@bp.post("/recarga/descontos")
def create_recarga_desconto():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    parsed, msg_err = _parse_discount_create(body)
    if msg_err:
        return jsonify(error=msg_err), 400
    assert parsed is not None
    nid = queries.create_recarga_desconto(
        parsed["nome"],
        parsed["gb_minimo"],
        parsed["percentual_desconto"],
        parsed["valor_fixo_reais"],
        parsed["ativo"],
        parsed["ordem"],
    )
    if not nid:
        return jsonify(error="Não foi possível criar desconto"), 409
    _audit(actor["username"], "recarga.desconto.create", "desconto", str(nid), parsed["nome"])
    rows = queries.list_recarga_descontos_admin()
    return jsonify(ok=True, descontos=[_serialize_discount_admin(r) for r in rows])


@bp.patch("/recarga/descontos/<int:did>")
def patch_recarga_desconto(did: int):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    row = queries.get_recarga_desconto_by_id(did)
    if not row:
        return jsonify(error="Desconto não encontrado"), 404
    body = request.get_json(silent=True) or {}
    parsed, msg_err = _parse_discount_patch(body)
    if msg_err:
        return jsonify(error=msg_err), 400
    assert parsed is not None

    ok_merge, merge_err = _discount_patch_merge_ok(row, parsed)
    if not ok_merge:
        return jsonify(error=merge_err), 400

    ok = queries.update_recarga_desconto_fields(did, parsed)
    if not ok:
        return jsonify(error="Não foi possível atualizar"), 409
    _audit(actor["username"], "recarga.desconto.update", "desconto", str(did), None)
    rows = queries.list_recarga_descontos_admin()
    return jsonify(ok=True, descontos=[_serialize_discount_admin(r) for r in rows])


def _mask_secret_preview(val: str | None) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    if len(s) <= 6:
        return "******"
    return f"******{s[-4:]}"


@bp.get("/pushinpay-config")
def get_pushinpay_config():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    from cpa_panel.services.pushinpay_credentials import merged_pushinpay_global

    row = queries.get_pushinpay_config_row()
    eff = merged_pushinpay_global()
    return jsonify(
        db_row_exists=row is not None,
        api_base=eff.get("api_base"),
        api_token_preview=_mask_secret_preview(eff.get("api_token")),
        api_token_configured=bool((eff.get("api_token") or "").strip()),
        site_public_url=eff.get("site_public_url") or "",
        webhook_header=eff.get("webhook_header") or "X-Webhook-Token",
        webhook_secret_configured=bool((eff.get("webhook_secret") or "").strip()),
        webhook_require_secret=bool(eff.get("webhook_require_secret")),
        recarga_pix_max_per_hour=int(eff.get("recarga_pix_max_per_hour") or 30),
        env_fallback_note="Campos vazios no banco usam variáveis de ambiente (PUSHINPAY_*, SITE_PUBLIC_URL).",
    )


@bp.patch("/pushinpay-config")
def patch_pushinpay_config():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    fields: dict = {}

    if "api_base" in body:
        v = body.get("api_base")
        fields["api_base"] = None if v is None or str(v).strip() == "" else str(v).strip()[:256]
    if "api_token" in body:
        v = body.get("api_token")
        fields["api_token"] = None if v is None or str(v).strip() == "" else str(v).strip()
    if "site_public_url" in body:
        v = body.get("site_public_url")
        fields["site_public_url"] = None if v is None or str(v).strip() == "" else str(v).strip().rstrip("/")[:512]
    if "webhook_secret" in body:
        v = body.get("webhook_secret")
        fields["webhook_secret"] = None if v is None or str(v).strip() == "" else str(v).strip()[:512]
    if "webhook_header" in body:
        v = body.get("webhook_header")
        fields["webhook_header"] = None if v is None or str(v).strip() == "" else str(v).strip()[:128]
    if "webhook_require_secret" in body:
        fields["webhook_require_secret"] = bool(body.get("webhook_require_secret"))
    if "recarga_pix_max_per_hour" in body:
        try:
            fields["recarga_pix_max_per_hour"] = max(1, min(500, int(body.get("recarga_pix_max_per_hour"))))
        except (TypeError, ValueError):
            return jsonify(error="recarga_pix_max_per_hour inválido"), 400

    if not fields:
        return jsonify(error="Nenhum campo para atualizar"), 400

    ok, uerr = queries.update_pushinpay_config_fields(fields)
    if not ok:
        return jsonify(error=uerr or "Falha ao gravar"), 400
    _audit(actor["username"], "pushinpay.config.update", "pushinpay", "1", str(list(fields.keys())))
    from cpa_panel.services.pushinpay_credentials import merged_pushinpay_global

    eff = merged_pushinpay_global()
    row_after = queries.get_pushinpay_config_row()
    return jsonify(
        ok=True,
        db_row_exists=row_after is not None,
        api_base=eff.get("api_base"),
        api_token_preview=_mask_secret_preview(eff.get("api_token")),
        api_token_configured=bool((eff.get("api_token") or "").strip()),
        site_public_url=eff.get("site_public_url") or "",
        webhook_header=eff.get("webhook_header") or "X-Webhook-Token",
        webhook_secret_configured=bool((eff.get("webhook_secret") or "").strip()),
        webhook_require_secret=bool(eff.get("webhook_require_secret")),
        recarga_pix_max_per_hour=int(eff.get("recarga_pix_max_per_hour") or 30),
        env_fallback_note="Campos vazios no banco usam variáveis de ambiente (PUSHINPAY_*, SITE_PUBLIC_URL).",
    )


@bp.delete("/recarga/descontos/<int:did>")
def delete_recarga_desconto(did: int):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "recarga.manage")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    if not queries.delete_recarga_desconto(did):
        return jsonify(error="Desconto não encontrado"), 404
    _audit(actor["username"], "recarga.desconto.delete", "desconto", str(did), None)
    rows = queries.list_recarga_descontos_admin()
    return jsonify(ok=True, descontos=[_serialize_discount_admin(r) for r in rows])


def _serialize_blocked_row(r: dict) -> dict:
    item = dict(r)
    if item.get("created_at"):
        item["created_at"] = _serialize_ts(item["created_at"])
    item["ativo"] = int(item.get("ativo") or 0)
    return item


@bp.get("/blocked-hosts")
def admin_list_blocked_hosts():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "hosts.block")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    rows = queries.list_blocked_hosts_admin()
    return jsonify(entries=[_serialize_blocked_row(dict(r)) for r in rows])


@bp.post("/blocked-hosts")
def admin_create_blocked_host():
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "hosts.block")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    body = request.get_json(silent=True) or {}
    raw_dom = body.get("dominio") or body.get("domain") or ""
    nota = body.get("nota")
    nota_s = str(nota).strip()[:255] if nota is not None and str(nota).strip() else None
    try:
        dom = _normalize_domain(str(raw_dom))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    nid, err_msg = queries.insert_blocked_host(dom, nota_s)
    if not nid:
        return jsonify(error=err_msg or "Falha ao cadastrar"), 409
    _audit(actor["username"], "hosts.block.add", "blocked_host", dom, nota_s)
    rows = queries.list_blocked_hosts_admin()
    return jsonify(ok=True, entries=[_serialize_blocked_row(dict(r)) for r in rows])


@bp.delete("/blocked-hosts/<int:bid>")
def admin_delete_blocked_host(bid: int):
    c, err = _ctx()
    if err:
        return err
    actor, rbac = c
    try:
        require_perm(rbac, "hosts.block")
    except PermissionError as e:
        return jsonify(error=str(e)), 403
    if not queries.delete_blocked_host(bid):
        return jsonify(error="Registro não encontrado"), 404
    _audit(actor["username"], "hosts.block.remove", "blocked_host", str(bid), None)
    rows = queries.list_blocked_hosts_admin()
    return jsonify(ok=True, entries=[_serialize_blocked_row(dict(r)) for r in rows])
