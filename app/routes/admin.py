"""Rotas da API administrativa (/api/v1/admin/*)."""

from flask import Blueprint, jsonify, request

from app.service.login import intentificar_painel
from app.service.segury import payload_from_authorization_header

admin_bp = Blueprint("admin_v1", __name__, url_prefix="/api/v1/admin")


def _credential_from_body(body: dict | None) -> str | None:
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


def _authenticated_admin_or_error_response():
    """Valida Bearer com role admin."""
    try:
        payload = payload_from_authorization_header(request.headers.get("Authorization"))
    except Exception as e:
        return None, (jsonify({"status": False, "message": str(e)}), 403)

    if payload.get("role") != "admin":
        return None, (
            jsonify({"status": False, "message": "Acesso restrito a administradores"}),
            403,
        )

    admin_id = payload.get("sub")
    if not admin_id:
        return None, (jsonify({"status": False, "message": "Token malformado"}), 403)

    return (payload, int(admin_id)), None


def _require_dono_or_error_response(admin_id: int):
    """Somente cargo Dono pode gerenciar contas administrativas."""
    from db.queries_usuario import admin_is_dono, get_admin_por_id

    base = get_admin_por_id(admin_id)
    if not base["status"]:
        return None, (jsonify({"status": False, "message": base["message"]}), 403)
    if not admin_is_dono(base["user"]):
        return None, (
            jsonify({
                "status": False,
                "message": "Apenas o cargo Dono pode gerenciar administradores",
            }),
            403,
        )
    return base["user"], None


def _require_permission_or_error_response(admin_id: int, permission: str):
    from db.queries_usuario import admin_has_permission_code, get_admin_completo

    base = get_admin_completo(admin_id)
    if not base["status"]:
        return None, (jsonify({"status": False, "message": base["message"]}), 403)
    user = base["user"]
    if not admin_has_permission_code(user, permission):
        return None, (
            jsonify({
                "status": False,
                "message": f"Permissão necessária: {permission}",
            }),
            403,
        )
    return user, None


@admin_bp.route("/login", methods=["POST"])
def admin_login_route():
    """Login unificado (mesma credencial que POST /api/v1/login)."""
    try:
        body = request.get_json(silent=True) or {}
        credential = _credential_from_body(body)
        if not credential:
            return jsonify({
                "status": False,
                "message": "Informe a credencial (host:porta:usuario:senha)",
            }), 400
        data = intentificar_painel(credential)
        if not data["status"]:
            return jsonify(data), 400
        return jsonify(data), 200
    except Exception as e:
        return jsonify({
            "status": False,
            "message": f"Erro ao identificar painel: {e}",
        }), 500


@admin_bp.route("/proxy-hosts", methods=["GET"])
def admin_list_proxy_hosts_route():
    from db.queires import list_proxy_hosts

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    data = list_proxy_hosts(only_active=False)
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/proxy-hosts", methods=["POST"])
def admin_create_proxy_host_route():
    from db.queires import insert_proxy_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    body = request.get_json(silent=True) or {}
    hostname = body.get("hostname")
    if not hostname:
        return jsonify({"status": False, "message": "hostname é obrigatório"}), 400

    sort_order = int(body.get("sort_order") or 0)
    data = insert_proxy_host(str(hostname), sort_order)
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 201


@admin_bp.route("/proxy-hosts/<int:host_id>", methods=["PATCH"])
def admin_update_proxy_host_route(host_id: int):
    from db.queires import update_proxy_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    body = request.get_json(silent=True) or {}
    data = update_proxy_host(
        host_id,
        hostname=body.get("hostname"),
        sort_order=body.get("sort_order"),
        ativo=body.get("ativo"),
    )
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/proxy-hosts/<int:host_id>", methods=["DELETE"])
def admin_delete_proxy_host_route(host_id: int):
    from db.queires import delete_proxy_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    data = delete_proxy_host(host_id)
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/blocked-hosts", methods=["GET"])
def admin_list_blocked_hosts_route():
    from db.queries_blocked_hosts import list_blocked_hosts

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.view")
    if err:
        body, code = err
        return body, code

    data = list_blocked_hosts(only_active=False)
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/blocked-hosts", methods=["POST"])
def admin_create_blocked_host_route():
    from db.queries_blocked_hosts import insert_blocked_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.create")
    if err:
        body, code = err
        return body, code

    body = request.get_json(silent=True) or {}
    hostname = body.get("hostname")
    if not hostname:
        return jsonify({"status": False, "message": "hostname é obrigatório"}), 400

    sort_order = int(body.get("sort_order") or 0)
    host_v = str(hostname).strip()
    data = insert_blocked_host(host_v, sort_order)
    if not data["status"]:
        return jsonify(data), 400

    from app.service.sub_usuarios import apply_blocked_hostname_to_all_subusers

    applied = apply_blocked_hostname_to_all_subusers(data.get("hostname") or host_v)
    data["apply"] = {
        "updated": applied.get("updated", 0),
        "unchanged": applied.get("unchanged", 0),
        "failed": len(applied.get("failed") or []),
        "message": applied.get("message"),
    }
    data["message"] = (
        f"Domínio cadastrado e bloqueado na API para "
        f"{applied.get('updated', 0)} sub-usuário(s)."
    )
    return jsonify(data), 201


@admin_bp.route("/blocked-hosts/<int:host_id>", methods=["PATCH"])
def admin_update_blocked_host_route(host_id: int):
    from db.queries_blocked_hosts import get_blocked_host_row, update_blocked_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.update")
    if err:
        body, code = err
        return body, code

    before = get_blocked_host_row(host_id)
    if not before.get("status"):
        return jsonify(before), 404
    row_hostname = before["host"]["hostname"]
    was_active = bool(before["host"].get("ativo"))

    body = request.get_json(silent=True) or {}
    data = update_blocked_host(
        host_id,
        hostname=body.get("hostname"),
        sort_order=body.get("sort_order"),
        ativo=body.get("ativo"),
    )
    if not data["status"]:
        return jsonify(data), 400

    if body.get("ativo") is not None:
        from app.service.sub_usuarios import (
            apply_blocked_hostname_to_all_subusers,
            remove_blocked_hostname_from_all_subusers,
        )

        ativo_val = body.get("ativo")
        now_active = ativo_val in (1, True, "1", "true")
        if was_active and not now_active:
            api_res = remove_blocked_hostname_from_all_subusers(row_hostname)
        elif not was_active and now_active:
            api_res = apply_blocked_hostname_to_all_subusers(row_hostname)
        else:
            api_res = {"status": True, "updated": 0, "unchanged": 0, "failed": [], "message": "Sem alteração na API"}

        data["apply"] = {
            "updated": api_res.get("updated", 0),
            "unchanged": api_res.get("unchanged", 0),
            "failed": len(api_res.get("failed") or []),
            "message": api_res.get("message"),
        }
        if was_active and not now_active:
            data["message"] = (
                f"Domínio desativado e removido da API em {api_res.get('updated', 0)} sub-usuário(s)."
            )
        elif not was_active and now_active:
            data["message"] = (
                f"Domínio ativado e bloqueado na API em {api_res.get('updated', 0)} sub-usuário(s)."
            )
    return jsonify(data), 200


@admin_bp.route("/blocked-hosts/<int:host_id>", methods=["DELETE"])
def admin_delete_blocked_host_route(host_id: int):
    from db.queries_blocked_hosts import delete_blocked_host

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.update")
    if err:
        body, code = err
        return body, code

    data = delete_blocked_host(host_id)
    if not data["status"]:
        return jsonify(data), 400

    from app.service.sub_usuarios import remove_blocked_hostname_from_all_subusers

    removed = data.get("hostname")
    api_res = remove_blocked_hostname_from_all_subusers(removed) if removed else None
    data["removed_hostname"] = removed
    if api_res:
        data["apply"] = {
            "updated": api_res.get("updated", 0),
            "unchanged": api_res.get("unchanged", 0),
            "failed": len(api_res.get("failed") or []),
            "message": api_res.get("message"),
        }
        data["message"] = (
            f"Domínio excluído e removido da API em {api_res.get('updated', 0)} sub-usuário(s)."
        )
    return jsonify(data), 200


@admin_bp.route("/subusers/sync-blocked-hosts", methods=["POST"])
def admin_sync_subusers_blocked_hosts_route():
    from app.service.sub_usuarios import sync_all_subusers_panel_blocked_hosts

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.create")
    if err:
        body, code = err
        return body, code

    data = sync_all_subusers_panel_blocked_hosts()
    if not data.get("status"):
        return jsonify(data), 400
    code = 207 if data.get("failed") else 200
    return jsonify(data), code


@admin_bp.route("/admin-users", methods=["GET"])
def admin_list_admin_users_route():
    from db.queries_usuario import list_admin_users

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_dono_or_error_response(admin_id)
    if err:
        body, code = err
        return body, code

    data = list_admin_users()
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/admin-users/cargos", methods=["GET"])
def admin_list_assignable_cargos_route():
    from db.queries_usuario import list_cargos_assignable_for_admin

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_dono_or_error_response(admin_id)
    if err:
        body, code = err
        return body, code

    data = list_cargos_assignable_for_admin()
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/admin-users", methods=["POST"])
def admin_create_admin_user_route():
    from db.queries_usuario import create_admin_user, get_admin_por_id

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    actor_row, err = _require_dono_or_error_response(admin_id)
    if err:
        body, code = err
        return body, code

    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    nome = body.get("nome")
    email = body.get("email")
    cargo_id = body.get("cargo_id")

    if not username or not password or not nome or cargo_id is None:
        return jsonify({
            "status": False,
            "message": "Campos obrigatórios: username, password, nome, cargo_id",
        }), 400

    raw_limite = body.get("limite_gb")
    limite_gb = None
    if raw_limite is not None and raw_limite != "":
        try:
            limite_gb = float(raw_limite)
        except (TypeError, ValueError):
            return jsonify({"status": False, "message": "limite_gb inválido"}), 400

    actor = get_admin_por_id(admin_id)
    actor_username = actor["user"]["username"] if actor.get("status") else actor_row.get("username", "unknown")

    data = create_admin_user(
        username=str(username),
        password=str(password),
        nome=str(nome),
        email=str(email).strip() if email else None,
        cargo_id=int(cargo_id),
        actor_username=actor_username,
        limite_gb=limite_gb,
    )
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 201


@admin_bp.route("/admin-users/<int:user_id>", methods=["PATCH"])
def admin_update_admin_user_route(user_id: int):
    from db.queries_usuario import get_admin_por_id, update_admin_user

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    actor_row, err = _require_dono_or_error_response(ctx[1])
    if err:
        body, code = err
        return body, code

    body = request.get_json(silent=True) or {}
    nome = body.get("nome")
    cargo_id = body.get("cargo_id")
    ativo = body.get("ativo")
    password = body.get("password")

    limite_gb = None
    limite_gb_provided = "limite_gb" in body
    if limite_gb_provided:
        raw = body.get("limite_gb")
        if raw is not None and raw != "":
            try:
                limite_gb = float(raw)
            except (TypeError, ValueError):
                return jsonify({"status": False, "message": "limite_gb inválido"}), 400

    parsed_cargo = None
    if cargo_id is not None and cargo_id != "":
        try:
            parsed_cargo = int(cargo_id)
        except (TypeError, ValueError):
            return jsonify({"status": False, "message": "cargo_id inválido"}), 400

    parsed_ativo = None
    if ativo is not None and ativo != "":
        parsed_ativo = 1 if ativo in (True, 1, "1", "true", "ativo") else 0

    email_provided = "email" in body
    email_arg = str(body.get("email") or "").strip() or None if email_provided else None

    actor = get_admin_por_id(ctx[1])
    actor_username = actor["user"]["username"] if actor.get("status") else actor_row.get("username", "unknown")

    data = update_admin_user(
        user_id,
        actor_id=int(ctx[1]),
        actor_username=actor_username,
        nome=str(nome).strip() if nome is not None else None,
        email=email_arg,
        email_provided=email_provided,
        cargo_id=parsed_cargo,
        limite_gb=limite_gb,
        limite_gb_provided=limite_gb_provided,
        ativo=parsed_ativo,
        password=str(password) if password else None,
    )
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/pool-countries", methods=["GET"])
def admin_pool_countries_route():
    """Lista países disponíveis no pool (API DataImpulse) para o formulário de criação."""
    from app.service.sub_usuarios import get_all_paises_dict

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.view")
    if err:
        body, code = err
        return body, code

    data = get_all_paises_dict()
    if not data.get("status"):
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/subusers", methods=["GET"])
def admin_list_subusers_route():
    from app.service.admin_gb_pool import admin_uses_gb_pool
    from app.service.sub_usuarios import get_users_enriched_for_admin_page
    from db.queries_usuario import get_admin_completo

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    _, err = _require_permission_or_error_response(admin_id, "users.view")
    if err:
        body, code = err
        return body, code

    only_owner = None
    admin_base = get_admin_completo(admin_id)
    if admin_base.get("status"):
        actor = admin_base["user"]
        if admin_uses_gb_pool(actor):
            only_owner = str(actor.get("username") or "").strip() or None

    try:
        port = int(request.args.get("proxy_port") or 823)
    except (TypeError, ValueError):
        port = 823

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 10)), 100))
    except (TypeError, ValueError):
        limit = 10

    q = request.args.get("q") or request.args.get("search")
    status = request.args.get("status") or "all"
    sort = request.args.get("sort") or "id_desc"

    data = get_users_enriched_for_admin_page(
        proxy_port=port,
        page=page,
        limit=limit,
        q=q,
        status=status,
        sort=sort,
        only_criado_por=only_owner,
    )
    if not data["status"]:
        return jsonify(data), 400
    return jsonify(data), 200


@admin_bp.route("/subusers", methods=["POST"])
@admin_bp.route("/create-subuser", methods=["POST"])
def admin_create_subuser_route():
    from app.service.sub_usuarios import create_subuser_with_balance

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        body, code = err
        return body, code

    _, admin_id = ctx
    actor, err = _require_permission_or_error_response(admin_id, "users.create")
    if err:
        body, code = err
        return body, code

    from db.queires import resolve_proxy_hosts_selection

    body = request.get_json(silent=True) or {}
    label = body.get("label")
    traffic_gb = body.get("traffic_gb", body.get("limit_gb"))
    login = body.get("login")
    password = body.get("password")
    threads = body.get("threads", 100)
    user_random = body.get("user_random", True)
    quantity = body.get("quantity", body.get("count", 1))

    if label is None or str(label).strip() == "":
        return jsonify({"status": False, "message": "Campo obrigatório: label"}), 400
    if traffic_gb is None:
        return jsonify({
            "status": False,
            "message": "Campo obrigatório: traffic_gb (GB de saldo inicial)",
        }), 400

    try:
        qty = int(quantity)
    except (TypeError, ValueError):
        return jsonify({"status": False, "message": "quantity deve ser um número inteiro"}), 400
    if qty < 1:
        return jsonify({"status": False, "message": "quantity deve ser pelo menos 1"}), 400

    criado_por = str(actor.get("username") or "admin")

    from app.service.admin_gb_pool import assert_can_allocate_subuser_gb

    try:
        traffic_f = float(traffic_gb)
    except (TypeError, ValueError):
        return jsonify({"status": False, "message": "traffic_gb inválido"}), 400
    ok_pool, pool_err = assert_can_allocate_subuser_gb(
        actor,
        traffic_gb=traffic_f,
        quantity=qty,
    )
    if not ok_pool:
        _audit(
            criado_por,
            "subuser.create.denied",
            "subuser",
            str(label).strip()[:120],
            pool_err,
        )
        return jsonify({
            "status": False,
            "message": pool_err,
            "code": "gb_pool_insufficient",
        }), 400

    hosts_raw = body.get("hosts") or body.get("hostnames")
    if isinstance(hosts_raw, str):
        hosts_raw = [hosts_raw]
    hosts_res = resolve_proxy_hosts_selection(
        hosts_raw if isinstance(hosts_raw, list) else None
    )
    if not hosts_res["status"]:
        return jsonify(hosts_res), 400
    hosts_list: list[str] = hosts_res["hosts"]
    proxy_port = int(body.get("proxy_port") or 823)

    countries_raw = body.get("countries") or body.get("pais")
    if isinstance(countries_raw, str):
        countries_raw = [countries_raw]
    countries_list: list[str] | None = (
        [str(c).strip() for c in countries_raw if str(c).strip()]
        if isinstance(countries_raw, list) and countries_raw
        else None
    )

    def _attach_credential(item: dict, hostname: str) -> dict:
        login_out = item.get("login", "")
        pass_out = item.get("password", "")
        item["hostname"] = hostname
        item["credential"] = f"{hostname}:{proxy_port}:{login_out}:{pass_out}"
        return item

    if qty > 1:
        from app.service.sub_usuarios import create_subusers_batch_with_balance

        if login and str(login).strip():
            return jsonify({
                "status": False,
                "message": "Criação em lote exige login automático (não informe login manual)",
            }), 400

        data = create_subusers_batch_with_balance(
            label=str(label).strip(),
            traffic_gb=traffic_gb,
            quantity=qty,
            threads=int(threads) if threads is not None else 100,
            criado_por=criado_por,
            countries=countries_list,
        )
        for idx, item in enumerate(data.get("created") or []):
            host = hosts_list[idx % len(hosts_list)]
            _attach_credential(item, host)
        if data.get("created"):
            data["credentials"] = [c.get("credential") for c in data["created"] if c.get("credential")]
            data["hosts_used"] = hosts_list

        if not data["status"]:
            return jsonify(data), 400
        created_n = len(data.get("created") or [])
        _audit(
            criado_por,
            "subuser.create.batch",
            "subuser",
            str(label).strip()[:120],
            f"qty={qty} gb={traffic_f} ok={created_n}",
        )
        code = 207 if data.get("failed") else 201
        return jsonify(data), code

    login_str = str(login).strip() if login else ""
    if login_str and bool(user_random):
        user_random = False

    data = create_subuser_with_balance(
        label=str(label).strip(),
        traffic_gb=traffic_gb,
        login=login_str or None,
        password=str(password) if password else None,
        threads=int(threads) if threads is not None else 100,
        user_random=not login_str and bool(user_random),
        criado_por=criado_por,
        countries=countries_list,
    )
    if not data["status"]:
        code = 207 if data.get("partial") else 400
        return jsonify(data), code

    _attach_credential(data, hosts_list[0])
    data["hosts_used"] = hosts_list
    login_out = data.get("login") or login_str or ""
    _audit(
        criado_por,
        "subuser.create",
        "subuser",
        str(login_out)[:120] or str(label).strip()[:120],
        f"gb={traffic_f} label={str(label).strip()[:80]}",
    )
    return jsonify(data), 201


def _mask_secret_preview(secret: str | None) -> str | None:
    s = (secret or "").strip()
    if not s:
        return None
    if len(s) <= 4:
        return "****"
    return f"******{s[-4:]}"


def _serialize_dt(v):
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v)


def _payments_view_or_error(admin_id: int):
    from db.queries_usuario import admin_has_permission_code, get_admin_completo

    base = get_admin_completo(admin_id)
    if not base["status"]:
        return None, (jsonify({"status": False, "message": base["message"]}), 403)
    user = base["user"]
    if admin_has_permission_code(user, "payments.manage") or admin_has_permission_code(user, "payments.view"):
        return user, None
    return None, (
        jsonify({
            "status": False,
            "message": "Permissão necessária: payments.view ou payments.manage",
        }),
        403,
    )


def _logs_payments_or_error(admin_id: int):
    from db.queries_usuario import admin_has_permission_code, get_admin_completo

    base = get_admin_completo(admin_id)
    if not base["status"]:
        return None, (jsonify({"status": False, "message": base["message"]}), 403)
    user = base["user"]
    if user.get("cargo", {}).get("bypass_all"):
        return user, None
    if (
        admin_has_permission_code(user, "logs.payments")
        or admin_has_permission_code(user, "payments.manage")
    ):
        return user, None
    return None, (
        jsonify({"status": False, "message": "Permissão necessária: logs.payments"}),
        403,
    )


def _audit(actor_username: str, action: str, target_type: str, target_key: str, detail: str | None = None):
    from app.service.audit_log import write_audit

    write_audit(actor_username, action, target_type, target_key, detail)


@admin_bp.route("/summary", methods=["GET"])
def admin_summary_route():
    from app.service.pushinpay_credentials import merged_pushinpay_global
    from db import queries_recarga as q
    from db.queries_usuario import admin_has_permission_code, count_audit_logs, get_admin_completo

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _require_permission_or_error_response(admin_id, "dashboard.view")
    if perm_err:
        return perm_err

    admin_base = get_admin_completo(admin_id)
    if not admin_base["status"]:
        return jsonify({"status": False, "message": admin_base["message"]}), 403
    admin_user = admin_base["user"]
    can_payments = admin_has_permission_code(admin_user, "payments.manage") or admin_has_permission_code(
        admin_user, "payments.view"
    )
    can_logs_pay = admin_has_permission_code(admin_user, "logs.payments") or admin_has_permission_code(
        admin_user, "payments.manage"
    )
    can_audit = admin_has_permission_code(admin_user, "logs.audit") or bool(admin_user.get("cargo", {}).get("bypass_all"))

    out = {
        "status": True,
        "username": admin_user.get("username"),
        "pushinpay_configured": False,
        "recarga_preco_por_gb": None,
        "pedidos": None,
        "payment_logs_total": None,
        "audit_logs_total": None,
    }

    if can_payments:
        eff = merged_pushinpay_global()
        out["pushinpay_configured"] = bool((eff.get("api_token") or "").strip())
        cfg = q.get_recarga_por_gb_config()
        out["recarga_preco_por_gb"] = float(cfg["preco_por_gb_reais"])
        out["pedidos"] = q.recarga_pedidos_stats()

    if can_logs_pay:
        out["payment_logs_total"] = q.count_recarga_payment_logs_all()

    if can_audit:
        out["audit_logs_total"] = count_audit_logs()

    from app.service.admin_gb_pool import admin_uses_gb_pool
    from db.queries_usuario import get_admin_gb_pool_summary

    if admin_uses_gb_pool(admin_user):
        pool = get_admin_gb_pool_summary(str(admin_user.get("username") or ""))
        out["gb_pool"] = {**pool, "applies": True}
    else:
        out["gb_pool"] = {"applies": False}

    return jsonify(out), 200


@admin_bp.route("/gb-pool", methods=["GET"])
def admin_gb_pool_route():
    """Resumo do pool de GB do revendedor (cargo socio)."""
    from app.service.admin_gb_pool import admin_uses_gb_pool
    from db.queries_usuario import get_admin_completo, get_admin_gb_pool_summary

    ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = ctx
    base = get_admin_completo(admin_id)
    if not base.get("status"):
        return jsonify({"status": False, "message": base.get("message")}), 403
    user = base["user"]
    if not admin_uses_gb_pool(user):
        return jsonify({
            "status": True,
            "applies": False,
            "message": "Pool de GB não se aplica a este cargo.",
        }), 200
    pool = get_admin_gb_pool_summary(str(user.get("username") or ""))
    return jsonify({"status": True, "applies": True, **pool}), 200


@admin_bp.route("/payment-logs", methods=["GET"])
def admin_payment_logs_route():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _logs_payments_or_error(admin_id)
    if perm_err:
        return perm_err

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 500))
    except (TypeError, ValueError):
        limit = 100
    uf = request.args.get("username")
    username_filter = str(uf).strip() if uf else None
    offset = page * limit

    db_status = q.payment_logs_db_status()
    backfill_result = None
    if request.args.get("backfill", "").lower() in ("1", "true", "yes"):
        backfill_result = q.backfill_recarga_payment_logs_from_pedidos()

    ok_count, total, err_count = q.count_payment_logs_unified(username_filter)
    if not ok_count:
        return jsonify({
            "status": False,
            "message": err_count or "Não foi possível ler os logs de pagamento",
            "logs": [],
            "total": 0,
            "db_status": db_status,
            "backfill": backfill_result,
        }), 200

    ok_list, rows, err_list = q.list_payment_logs_unified(limit, offset, username_filter)
    if not ok_list:
        return jsonify({
            "status": False,
            "message": err_list or "Não foi possível listar os logs",
            "logs": [],
            "total": 0,
            "db_status": db_status,
            "backfill": backfill_result,
        }), 200

    logs = []
    for r in rows:
        o = dict(r)
        o["created_at"] = _serialize_dt(o.get("created_at"))
        if o.get("meta") is not None and not isinstance(o.get("meta"), str):
            try:
                import json as _json

                o["meta"] = _json.dumps(o["meta"], ensure_ascii=False, default=str)
            except Exception:
                o["meta"] = str(o["meta"])
        if o.get("pedido_valor_reais") is not None:
            o["pedido_valor_reais"] = float(o["pedido_valor_reais"])
        if o.get("pedido_gb_credito") is not None:
            o["pedido_gb_credito"] = float(o["pedido_gb_credito"])
        logs.append(o)

    return jsonify({
        "status": True,
        "logs": logs,
        "page": page,
        "limit": limit,
        "total": total,
        "db_status": db_status,
        "backfill": backfill_result,
    }), 200


@admin_bp.route("/payment-logs/backfill", methods=["POST"])
def admin_payment_logs_backfill_route():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

    result = q.backfill_recarga_payment_logs_from_pedidos()
    return jsonify({"status": bool(result.get("status")), **result}), 200 if result.get("status") else 400


@admin_bp.route("/recarga/pedidos", methods=["GET"])
def admin_recarga_pedidos_route():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _payments_view_or_error(admin_id)
    if perm_err:
        return perm_err

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    st = request.args.get("status")
    status_filter = str(st).strip() if st else None
    uf = request.args.get("username")
    username_filter = str(uf).strip() if uf else None
    offset = page * limit

    rows = q.list_recarga_pedidos_pix_admin(limit, offset, status_filter, username_filter)
    total = q.count_recarga_pedidos_pix_admin(status_filter, username_filter)
    pedidos = []
    for r in rows:
        o = dict(r)
        o["criado_em"] = _serialize_dt(o.get("criado_em"))
        o["atualizado_em"] = _serialize_dt(o.get("atualizado_em"))
        if o.get("valor_reais") is not None:
            o["valor_reais"] = float(o["valor_reais"])
        if o.get("gb_credito") is not None:
            o["gb_credito"] = float(o["gb_credito"])
        pedidos.append(o)

    return jsonify({"status": True, "pedidos": pedidos, "page": page, "limit": limit, "total": total}), 200


@admin_bp.route("/audit-logs", methods=["GET"])
def admin_audit_logs_route():
    from db.queries_usuario import count_audit_logs, list_audit_logs

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _require_permission_or_error_response(admin_id, "logs.audit")
    if perm_err:
        return perm_err

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    offset = page * limit

    rows = list_audit_logs(limit, offset)
    total = count_audit_logs()
    logs = []
    for r in rows:
        o = dict(r)
        o["created_at"] = _serialize_dt(o.get("created_at"))
        logs.append(o)

    return jsonify({"status": True, "logs": logs, "page": page, "limit": limit, "total": total}), 200


@admin_bp.route("/pushinpay-config", methods=["GET"])
def admin_pushinpay_config_get():
    from app.service.pushinpay_credentials import merged_pushinpay_global
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _payments_view_or_error(admin_id)
    if perm_err:
        return perm_err

    eff = merged_pushinpay_global()
    row = q.get_pushinpay_config_row()
    return jsonify({
        "status": True,
        "db_row_exists": row is not None,
        "api_base": eff.get("api_base"),
        "api_token_preview": _mask_secret_preview(eff.get("api_token")),
        "api_token_configured": bool((eff.get("api_token") or "").strip()),
        "site_public_url": eff.get("site_public_url") or "",
        "webhook_header": eff.get("webhook_header") or "X-Webhook-Token",
        "webhook_secret_configured": bool((eff.get("webhook_secret") or "").strip()),
        "webhook_require_secret": bool(eff.get("webhook_require_secret")),
        "webhook_force_secret": bool(eff.get("webhook_force_secret")),
        "recarga_pix_max_per_hour": int(eff.get("recarga_pix_max_per_hour") or 30),
        "recarga_pix_sync_max_per_hour": int(eff.get("recarga_pix_sync_max_per_hour") or 60),
        "config_source": "mysql",
        "webhook_url": f"{eff.get('site_public_url') or ''}/api/webhooks/pushinpay/pix".rstrip("/")
        if eff.get("site_public_url")
        else "",
    }), 200


@admin_bp.route("/pushinpay-config", methods=["PATCH"])
def admin_pushinpay_config_patch():
    from app.service.pushinpay_credentials import merged_pushinpay_global
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

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
            return jsonify({"status": False, "message": "recarga_pix_max_per_hour inválido"}), 400
    if "recarga_pix_sync_max_per_hour" in body:
        try:
            fields["recarga_pix_sync_max_per_hour"] = max(1, min(500, int(body.get("recarga_pix_sync_max_per_hour"))))
        except (TypeError, ValueError):
            return jsonify({"status": False, "message": "recarga_pix_sync_max_per_hour inválido"}), 400
    if "webhook_force_secret" in body:
        fields["webhook_force_secret"] = bool(body.get("webhook_force_secret"))

    if not fields:
        return jsonify({"status": False, "message": "Nenhum campo para atualizar"}), 400

    eff_pre = merged_pushinpay_global()
    wh_after = fields.get("webhook_secret")
    if wh_after is None:
        wh_after = eff_pre.get("webhook_secret") or ""
    else:
        wh_after = str(wh_after).strip()
    req_after = fields.get("webhook_require_secret")
    if req_after is None:
        req_after = bool(eff_pre.get("webhook_require_secret"))
    if req_after and not wh_after:
        return jsonify({
            "status": False,
            "message": "Defina o segredo do webhook antes de exigir validação.",
        }), 400
    force_after = fields.get("webhook_force_secret")
    if force_after is None:
        force_after = bool(eff_pre.get("webhook_force_secret"))
    if force_after and fields.get("webhook_require_secret") is False:
        return jsonify({
            "status": False,
            "message": "Com 'forçar segredo no webhook' ativo, não é permitido desativar a validação.",
        }), 400

    ok, uerr = q.update_pushinpay_config_fields(fields)
    if not ok:
        return jsonify({"status": False, "message": uerr or "Falha ao gravar"}), 400

    from app.service.payment_logging import log_payment_event

    log_payment_event(
        "admin_pushinpay_config_update",
        "admin",
        severity="info",
        meta={"campos": list(fields.keys()), "actor": actor["username"]},
    )
    _audit(actor["username"], "pushinpay.config.update", "pushinpay", "1", str(list(fields.keys())))

    eff = merged_pushinpay_global()
    return jsonify({
        "status": True,
        "api_base": eff.get("api_base"),
        "api_token_preview": _mask_secret_preview(eff.get("api_token")),
        "api_token_configured": bool((eff.get("api_token") or "").strip()),
        "site_public_url": eff.get("site_public_url") or "",
        "webhook_header": eff.get("webhook_header") or "X-Webhook-Token",
        "webhook_secret_configured": bool((eff.get("webhook_secret") or "").strip()),
        "webhook_require_secret": bool(eff.get("webhook_require_secret")),
        "webhook_force_secret": bool(eff.get("webhook_force_secret")),
        "recarga_pix_max_per_hour": int(eff.get("recarga_pix_max_per_hour") or 30),
        "recarga_pix_sync_max_per_hour": int(eff.get("recarga_pix_sync_max_per_hour") or 60),
    }), 200


@admin_bp.route("/recarga/config", methods=["GET"])
def admin_recarga_config_get():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _payments_view_or_error(admin_id)
    if perm_err:
        return perm_err

    cfg = q.get_recarga_por_gb_config()
    return jsonify({"status": True, **cfg}), 200


@admin_bp.route("/recarga/config", methods=["PATCH"])
def admin_recarga_config_patch():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

    body = request.get_json(silent=True) or {}
    fields: dict = {}
    for key in ("preco_por_gb_reais", "gb_min", "gb_max", "gb_step", "max_total_reais"):
        if key in body:
            try:
                fields[key] = float(body[key])
            except (TypeError, ValueError):
                return jsonify({"status": False, "message": f"{key} inválido"}), 400

    if not fields:
        return jsonify({"status": False, "message": "Nenhum campo para atualizar"}), 400

    ok, uerr = q.update_recarga_config_fields(fields)
    if not ok:
        return jsonify({"status": False, "message": uerr or "Falha ao gravar"}), 400

    _audit(actor["username"], "recarga.config.update", "recarga_config", "1", str(list(fields.keys())))

    return jsonify({"status": True, **q.get_recarga_por_gb_config()}), 200


@admin_bp.route("/recarga/descontos", methods=["GET"])
def admin_recarga_descontos_list():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _payments_view_or_error(admin_id)
    if perm_err:
        return perm_err

    rows = q.list_recarga_descontos_admin()
    out = []
    for r in rows:
        o = dict(r)
        for k in ("created_at", "updated_at"):
            v = o.get(k)
            if hasattr(v, "isoformat"):
                o[k] = v.isoformat()
        out.append(o)
    return jsonify({"status": True, "descontos": out}), 200


@admin_bp.route("/recarga/descontos", methods=["POST"])
def admin_recarga_desconto_create():
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

    body = request.get_json(silent=True) or {}
    nome = str(body.get("nome") or "").strip() or "Desconto"
    try:
        gb_min = float(body.get("gb_minimo"))
    except (TypeError, ValueError):
        return jsonify({"status": False, "message": "gb_minimo obrigatório"}), 400

    pct = body.get("percentual_desconto")
    fix = body.get("valor_fixo_reais")
    pct_f = float(pct) if pct is not None and str(pct).strip() != "" else None
    fix_f = float(fix) if fix is not None and str(fix).strip() != "" else None
    if (pct_f and pct_f > 0) == (fix_f and fix_f > 0):
        return jsonify({
            "status": False,
            "message": "Informe percentual_desconto OU valor_fixo_reais (apenas um)",
        }), 400

    nid = q.create_recarga_desconto(
        nome,
        gb_min,
        pct_f,
        fix_f,
        int(body.get("ativo", 1)),
        int(body.get("ordem", 0)),
    )
    if not nid:
        return jsonify({"status": False, "message": "Falha ao criar desconto"}), 400
    _audit(actor["username"], "recarga.desconto.create", "desconto", str(nid), nome)
    return jsonify({"status": True, "id": nid}), 201


@admin_bp.route("/recarga/descontos/<int:did>", methods=["PATCH"])
def admin_recarga_desconto_patch(did: int):
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

    body = request.get_json(silent=True) or {}
    fields = {k: body[k] for k in ("nome", "gb_minimo", "percentual_desconto", "valor_fixo_reais", "ativo", "ordem") if k in body}
    if not fields:
        return jsonify({"status": False, "message": "Nenhum campo para atualizar"}), 400

    ok = q.update_recarga_desconto_fields(did, fields)
    if not ok:
        return jsonify({"status": False, "message": "Desconto não encontrado ou falha ao atualizar"}), 404
    _audit(actor["username"], "recarga.desconto.update", "desconto", str(did), None)
    return jsonify({"status": True}), 200


@admin_bp.route("/recarga/descontos/<int:did>", methods=["DELETE"])
def admin_recarga_desconto_delete(did: int):
    from db import queries_recarga as q

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "payments.manage")
    if perm_err:
        return perm_err

    if not q.delete_recarga_desconto(did):
        return jsonify({"status": False, "message": "Desconto não encontrado"}), 404
    _audit(actor["username"], "recarga.desconto.delete", "desconto", str(did), None)
    return jsonify({"status": True}), 200


def _notif_perm_view_or_error(admin_id: int):
    return _require_permission_or_error_response(admin_id, "notifications.view")


@admin_bp.route("/notificacoes", methods=["GET"])
def admin_notificacoes_list_route():
    from db import queries_notificacoes as qn

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, perm_err = _notif_perm_view_or_error(admin_id)
    if perm_err:
        return perm_err

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    limit = 50
    offset = page * limit
    rows = qn.list_notificacoes_admin(limit, offset)
    total = qn.count_notificacoes_admin()
    items = []
    for r in rows:
        o = dict(r)
        o["criado_em"] = _serialize_dt(o.get("criado_em"))
        o["atualizado_em"] = _serialize_dt(o.get("atualizado_em"))
        o["expira_em"] = _serialize_dt(o.get("expira_em"))
        o["ativo"] = bool(int(o.get("ativo") or 0))
        items.append(o)
    return jsonify({"status": True, "notificacoes": items, "total": total, "page": page, "limit": limit}), 200


@admin_bp.route("/notificacoes", methods=["POST"])
def admin_notificacoes_create_route():
    from db import queries_notificacoes as qn

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "notifications.manage")
    if perm_err:
        return perm_err

    body = request.get_json(silent=True) or {}
    titulo = str(body.get("titulo") or "").strip()
    mensagem = str(body.get("mensagem") or "").strip()
    if not titulo or not mensagem:
        return jsonify({"status": False, "message": "titulo e mensagem são obrigatórios"}), 400

    tipo = str(body.get("tipo") or "normal").strip().lower()
    alvo_tipo = str(body.get("alvo_tipo") or "todos").strip().lower()
    subuser_ids = body.get("subuser_ids")
    ids_list = None
    if isinstance(subuser_ids, list):
        ids_list = [str(x).strip() for x in subuser_ids if str(x).strip()]

    nid, uerr = qn.create_notificacao(
        titulo=titulo,
        mensagem=mensagem,
        tipo=tipo,
        alvo_tipo=alvo_tipo,
        criado_por=actor["username"],
        subuser_ids=ids_list,
        expira_em=body.get("expira_em"),
    )
    if not nid:
        return jsonify({"status": False, "message": uerr or "Falha ao criar notificação"}), 400

    _audit(actor["username"], "notificacao.create", "notificacao", str(nid), f"{tipo}/{alvo_tipo}")
    row = qn.get_notificacao_admin(nid)
    return jsonify({"status": True, "id": nid, "notificacao": row}), 201


@admin_bp.route("/notificacoes/<int:nid>", methods=["PATCH"])
def admin_notificacoes_patch_route(nid: int):
    from db import queries_notificacoes as qn

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "notifications.manage")
    if perm_err:
        return perm_err

    body = request.get_json(silent=True) or {}
    if "ativo" not in body:
        return jsonify({"status": False, "message": "Informe ativo (true/false)"}), 400

    ativo = bool(body.get("ativo"))
    if not qn.update_notificacao_ativo(nid, ativo):
        return jsonify({"status": False, "message": "Notificação não encontrada"}), 404

    _audit(actor["username"], "notificacao.update", "notificacao", str(nid), f"ativo={ativo}")
    return jsonify({"status": True}), 200


@admin_bp.route("/notificacoes/<int:nid>", methods=["DELETE"])
def admin_notificacoes_delete_route(nid: int):
    from db import queries_notificacoes as qn

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, perm_err = _require_permission_or_error_response(admin_id, "notifications.manage")
    if perm_err:
        return perm_err

    if not qn.delete_notificacao_admin(nid):
        return jsonify({"status": False, "message": "Notificação não encontrada"}), 404

    _audit(actor["username"], "notificacao.delete", "notificacao", str(nid), None)
    return jsonify({"status": True}), 200


def _branding_public_payload():
    from db.queries_site_branding import get_site_branding
    from app.service.site_branding_public import branding_to_public_api

    data = get_site_branding()
    if not data["status"]:
        return data
    return {
        "status": True,
        "branding": branding_to_public_api(data.get("branding") or {}),
    }


@admin_bp.route("/site-branding", methods=["GET"])
def admin_site_branding_get_route():
    """Somente Dono — visualizar configuração de marca."""
    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    _, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    payload = _branding_public_payload()
    if not payload.get("status"):
        return jsonify(payload), 500
    return jsonify(payload), 200


@admin_bp.route("/site-branding", methods=["PATCH"])
def admin_site_branding_patch_route():
    """Somente Dono — atualizar textos da marca."""
    from db.queries_site_branding import update_site_branding

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    body = request.get_json(silent=True) or {}
    fields = {}
    for key in (
        "site_name",
        "site_tagline",
        "login_title",
        "login_subtitle",
        "footer_text",
        "support_email",
        "support_whatsapp",
        "logo_url",
    ):
        if key in body:
            fields[key] = body.get(key)

    if not fields:
        return jsonify({"status": False, "message": "Nenhum campo enviado"}), 400

    data = update_site_branding(fields, updated_by=actor.get("username"))
    if not data["status"]:
        return jsonify(data), 400

    _audit(
        actor["username"],
        "site_branding.update",
        "site_branding",
        "1",
        ",".join(fields.keys()),
    )
    payload = _branding_public_payload()
    return jsonify(payload), 200


@admin_bp.route("/site-branding/logo", methods=["POST"])
def admin_site_branding_logo_upload_route():
    from app.service.site_branding_files import save_branding_file
    from db.queries_site_branding import update_site_branding

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    file = request.files.get("file") or request.files.get("logo")
    saved = save_branding_file("logo", file)
    if not saved["status"]:
        return jsonify(saved), 400

    upd = update_site_branding(
        {"logo_filename": saved["filename"]},
        updated_by=actor.get("username"),
    )
    if not upd["status"]:
        return jsonify(upd), 400

    _audit(actor["username"], "site_branding.logo", "site_branding", "1", saved["filename"])
    payload = _branding_public_payload()
    return jsonify(payload), 200


@admin_bp.route("/site-branding/logo", methods=["DELETE"])
def admin_site_branding_logo_delete_route():
    from app.service.site_branding_files import remove_branding_file
    from db.queries_site_branding import update_site_branding

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    remove_branding_file("logo")
    update_site_branding({"logo_filename": None}, updated_by=actor.get("username"))
    _audit(actor["username"], "site_branding.logo_remove", "site_branding", "1", None)
    payload = _branding_public_payload()
    return jsonify(payload), 200


@admin_bp.route("/site-branding/favicon", methods=["POST"])
def admin_site_branding_favicon_upload_route():
    from app.service.site_branding_files import save_branding_file
    from db.queries_site_branding import update_site_branding

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    file = request.files.get("file") or request.files.get("favicon")
    saved = save_branding_file("favicon", file)
    if not saved["status"]:
        return jsonify(saved), 400

    upd = update_site_branding(
        {"favicon_filename": saved["filename"]},
        updated_by=actor.get("username"),
    )
    if not upd["status"]:
        return jsonify(upd), 400

    _audit(actor["username"], "site_branding.favicon", "site_branding", "1", saved["filename"])
    payload = _branding_public_payload()
    return jsonify(payload), 200


@admin_bp.route("/site-branding/favicon", methods=["DELETE"])
def admin_site_branding_favicon_delete_route():
    from app.service.site_branding_files import remove_branding_file
    from db.queries_site_branding import update_site_branding

    _ctx, err = _authenticated_admin_or_error_response()
    if err:
        return err
    _, admin_id = _ctx
    actor, dono_err = _require_dono_or_error_response(admin_id)
    if dono_err:
        return dono_err

    remove_branding_file("favicon")
    update_site_branding({"favicon_filename": None}, updated_by=actor.get("username"))
    _audit(actor["username"], "site_branding.favicon_remove", "site_branding", "1", None)
    payload = _branding_public_payload()
    return jsonify(payload), 200


def _socio_branding_actor_or_error():
    actor, err = _require_socio_actor_or_error()
    if err:
        return None, None, err
    from db.queries_usuario import admin_has_permission_code

    if not admin_has_permission_code(actor, "socio.branding.manage") and not admin_has_permission_code(
        actor, "dashboard.view"
    ):
        return None, None, (
            jsonify({"status": False, "message": "Permissão necessária: socio.branding.manage"}),
            403,
        )
    return actor, str(actor.get("username") or "").strip(), None


def _socio_branding_public_payload(username: str):
    from app.service.branding_resolve import merge_branding_public

    return merge_branding_public(revendedor_username=username)


def _require_socio_actor_or_error():
    """Revendedor autenticado (cargo socio)."""
    ctx, err = _authenticated_admin_or_error_response()
    if err:
        return None, err
    _, admin_id = ctx
    from db.queries_usuario import get_admin_completo

    data = get_admin_completo(admin_id)
    if not data.get("status"):
        return None, (jsonify(data), 400)
    actor = data["user"]
    slug = str(actor.get("cargo_slug") or actor.get("cargo", {}).get("slug") or "").strip().lower()
    if slug != "socio":
        return None, (
            jsonify({"status": False, "message": "Somente revendedores podem acessar este recurso."}),
            403,
        )
    return actor, None


@admin_bp.route("/socio/audit-logs", methods=["GET"])
def admin_socio_audit_logs_route():
    from db.queries_usuario import count_audit_logs_for_actor, list_audit_logs_for_actor

    actor, err = _require_socio_actor_or_error()
    if err:
        return err
    username = str(actor.get("username") or "").strip()

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    offset = page * limit

    rows = list_audit_logs_for_actor(username, limit, offset)
    total = count_audit_logs_for_actor(username)
    logs = []
    for r in rows:
        o = dict(r)
        o["created_at"] = _serialize_dt(o.get("created_at"))
        logs.append(o)
    return jsonify({"status": True, "logs": logs, "page": page, "limit": limit, "total": total}), 200


@admin_bp.route("/socio/recarga-pedidos", methods=["GET"])
def admin_socio_recarga_pedidos_route():
    from db import queries_recarga as q

    actor, err = _require_socio_actor_or_error()
    if err:
        return err
    username = str(actor.get("username") or "").strip()

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (TypeError, ValueError):
        page = 0
    try:
        limit = max(1, min(int(request.args.get("limit", 30)), 100))
    except (TypeError, ValueError):
        limit = 30
    st = request.args.get("status")
    status_filter = str(st).strip() if st else None
    offset = page * limit

    rows = q.list_recarga_pedidos_pix_for_socio(username, limit, offset, status_filter)
    total = q.count_recarga_pedidos_pix_for_socio(username, status_filter)
    pedidos = []
    for r in rows:
        o = dict(r)
        o["criado_em"] = _serialize_dt(o.get("criado_em"))
        o["atualizado_em"] = _serialize_dt(o.get("atualizado_em"))
        if o.get("valor_reais") is not None:
            o["valor_reais"] = float(o["valor_reais"])
        if o.get("gb_credito") is not None:
            o["gb_credito"] = float(o["gb_credito"])
        pedidos.append(o)
    return jsonify({"status": True, "pedidos": pedidos, "page": page, "limit": limit, "total": total}), 200


@admin_bp.route("/socio/report", methods=["GET"])
def admin_socio_report_route():
    from app.service.admin_gb_pool import admin_uses_gb_pool, get_admin_gb_pool_summary
    from db import queries_recarga as q
    from db.queries_usuario import count_audit_logs_for_actor

    actor, err = _require_socio_actor_or_error()
    if err:
        return err
    username = str(actor.get("username") or "").strip()

    pool = get_admin_gb_pool_summary(username) if admin_uses_gb_pool(actor) else None
    from db.queires import list_subusers_local_map

    lm = list_subusers_local_map()
    client_count = 0
    if lm.get("status"):
        for row in (lm.get("map") or {}).values():
            if str(row.get("criado_por") or "").strip() == username:
                client_count += 1

    return jsonify({
        "status": True,
        "gb_pool": {**pool, "applies": True} if pool else {"applies": False},
        "clientes_total": client_count,
        "recarga_pedidos_total": q.count_recarga_pedidos_pix_for_socio(username),
        "recarga_pedidos_pendentes": q.count_recarga_pedidos_pix_for_socio(username, "pending"),
        "audit_logs_total": count_audit_logs_for_actor(username),
    }), 200


@admin_bp.route("/socio-branding", methods=["GET"])
def admin_socio_branding_get_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from db.queries_socio_branding import get_socio_branding

    data = get_socio_branding(username)
    if not data.get("status"):
        return jsonify(data), 500
    from app.service.site_branding_public import branding_to_public_api

    public = branding_to_public_api(data.get("branding") or {}, socio_username=username)
    return jsonify({
        "status": True,
        "branding": public,
        "admin_username": username,
        "message": data.get("message"),
    }), 200


@admin_bp.route("/socio-branding", methods=["PATCH"])
def admin_socio_branding_patch_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from db.queries_socio_branding import update_socio_branding

    body = request.get_json(silent=True) or {}
    fields = {}
    for key in (
        "site_name",
        "site_tagline",
        "login_title",
        "login_subtitle",
        "footer_text",
        "support_email",
        "support_whatsapp",
        "logo_url",
    ):
        if key in body:
            fields[key] = body.get(key)
    if not fields:
        return jsonify({"status": False, "message": "Nenhum campo enviado"}), 400

    data = update_socio_branding(username, fields, updated_by=username)
    if not data.get("status"):
        return jsonify(data), 400
    _audit(username, "socio.branding.update", "socio_branding", username, ",".join(fields.keys()))
    payload = _socio_branding_public_payload(username)
    return jsonify(payload), 200


@admin_bp.route("/socio-branding/logo", methods=["POST"])
def admin_socio_branding_logo_upload_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from app.service.site_branding_files import save_socio_branding_file
    from db.queries_socio_branding import update_socio_branding

    file = request.files.get("file") or request.files.get("logo")
    saved = save_socio_branding_file(username, "logo", file)
    if not saved["status"]:
        return jsonify(saved), 400
    upd = update_socio_branding(
        username,
        {"logo_filename": saved["filename"], "logo_url": None},
        updated_by=username,
    )
    if not upd.get("status"):
        return jsonify(upd), 400
    _audit(username, "socio.branding.logo", "socio_branding", username, saved["filename"])
    return jsonify(_socio_branding_public_payload(username)), 200


@admin_bp.route("/socio-branding/logo", methods=["DELETE"])
def admin_socio_branding_logo_delete_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from app.service.site_branding_files import remove_socio_branding_file
    from db.queries_socio_branding import update_socio_branding

    remove_socio_branding_file(username, "logo")
    update_socio_branding(username, {"logo_filename": None}, updated_by=username)
    _audit(username, "socio.branding.logo_remove", "socio_branding", username, None)
    return jsonify(_socio_branding_public_payload(username)), 200


@admin_bp.route("/socio-branding/favicon", methods=["POST"])
def admin_socio_branding_favicon_upload_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from app.service.site_branding_files import save_socio_branding_file
    from db.queries_socio_branding import update_socio_branding

    file = request.files.get("file") or request.files.get("favicon")
    saved = save_socio_branding_file(username, "favicon", file)
    if not saved["status"]:
        return jsonify(saved), 400
    upd = update_socio_branding(
        username,
        {"favicon_filename": saved["filename"]},
        updated_by=username,
    )
    if not upd.get("status"):
        return jsonify(upd), 400
    _audit(username, "socio.branding.favicon", "socio_branding", username, saved["filename"])
    return jsonify(_socio_branding_public_payload(username)), 200


@admin_bp.route("/socio-branding/favicon", methods=["DELETE"])
def admin_socio_branding_favicon_delete_route():
    actor, username, err = _socio_branding_actor_or_error()
    if err:
        return err
    from app.service.site_branding_files import remove_socio_branding_file
    from db.queries_socio_branding import update_socio_branding

    remove_socio_branding_file(username, "favicon")
    update_socio_branding(username, {"favicon_filename": None}, updated_by=username)
    _audit(username, "socio.branding.favicon_remove", "socio_branding", username, None)
    return jsonify(_socio_branding_public_payload(username)), 200