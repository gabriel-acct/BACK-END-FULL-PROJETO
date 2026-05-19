from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from db.queires import get_subuser_local_by_login, get_token, update_token
import requests
from config import ResellerBackend

ResellerBackendData = ResellerBackend()

_SUBUSER_LIST_CACHE: dict = {"at": 0.0, "users": None}
_SUBUSER_LIST_CACHE_TTL_SEC = 120.0


def _is_rate_limit_message(message: str | None) -> bool:
    msg = (message or "").lower()
    return "too many attempt" in msg or "rate limit" in msg or "too many request" in msg


def _friendly_api_limit_message(message: str | None) -> str:
    if _is_rate_limit_message(message):
        return (
            "A API da proxy limitou as consultas (muitas tentativas). "
            "Aguarde 5–15 minutos e tente novamente."
        )
    return (message or "Erro ao consultar API da proxy").strip()
def _is_token_expired_response(data) -> bool:
    """Detecta token expirado em respostas da API (qualquer status HTTP)."""
    if not isinstance(data, dict):
        return False
    msg = str(data.get("message") or "").lower()
    if data.get("status") is False and "expired" in msg and "token" in msg:
        return True
    return msg in ("token has expired", "token expired")


def generate_new_token():
    url = f"{ResellerBackendData.API_URL}/reseller/user/token/get"

    payload = {
        "login": ResellerBackendData.LOGIN,
        "password": ResellerBackendData.PASSWORD,
    }
    try:
        r = requests.post(url, json=payload, timeout=20)
        response = r.json()
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}",
        }
    if not isinstance(response, dict) or not response.get("token"):
        detail = response.get("message") if isinstance(response, dict) else str(response)
        return {
            "status": False,
            "message": detail or "Token não encontrado na API",
        }
    return {
        "status": True,
        "message": "Token gerado com sucesso",
        "token": response["token"],
    }


def _refresh_reseller_token_in_db() -> dict:
    """Gera novo token na API e grava em proxys_private."""
    new_token = generate_new_token()
    if not new_token["status"]:
        return {
            "status": False,
            "message": new_token.get("message", "Falha ao renovar token da API"),
        }
    upd = update_token(new_token["token"])
    if isinstance(upd, dict) and not upd.get("status", True):
        return {
            "status": False,
            "message": upd.get("message", "Erro ao gravar token no banco"),
        }
    return {
        "status": True,
        "message": "Token renovado",
        "token": new_token["token"],
    }


def valid_token_and_generate_new_token(*, force_refresh: bool = False):
    if force_refresh:
        return _refresh_reseller_token_in_db()

    token_db = get_token()
    if not token_db["status"] or not token_db.get("token"):
        return _refresh_reseller_token_in_db()

    url = f"{ResellerBackendData.API_URL}/reseller/user/balance"
    headers = {
        "Authorization": f"Bearer {token_db['token']}",
    }
    try:
        r = requests.get(url, headers=headers, timeout=20)
        try:
            data = r.json()
        except ValueError:
            data = {"message": r.text}
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}",
        }

    if _is_token_expired_response(data):
        return _refresh_reseller_token_in_db()

    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida ao validar token",
            "response": data,
        }
    if r.status_code != 200:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro ao validar token"),
            "response": data,
        }

    return {
        "status": True,
        "message": "Token válido",
        "token": token_db["token"],
    }

def get_all_user(*, use_cache: bool = True):
    now = time.time()
    if use_cache and _SUBUSER_LIST_CACHE["users"] is not None:
        if now - float(_SUBUSER_LIST_CACHE["at"]) < _SUBUSER_LIST_CACHE_TTL_SEC:
            return {
                "status": True,
                "message": "Usuários (cache)",
                "users": _SUBUSER_LIST_CACHE["users"],
                "cached": True,
            }

    token = valid_token_and_generate_new_token()

    if not token["status"]:
        return {
            "status": False,
            "message": _friendly_api_limit_message(token.get("message")),
        }

    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/list"
    payload = {"token": token["token"]}

    def _fetch_list(api_token: str):
        try:
            r = requests.get(url, json={"token": api_token}, timeout=20)
            try:
                data = r.json()
            except ValueError:
                data = {"message": r.text}
            return r, data
        except Exception as e:
            return None, {"message": str(e)}

    r, data = _fetch_list(token["token"])
    if r is None:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {data.get('message')}",
        }

    if _is_token_expired_response(data):
        token = valid_token_and_generate_new_token(force_refresh=True)
        if not token["status"]:
            return {"status": False, "message": token["message"]}
        r, data = _fetch_list(token["token"])
        if r is None:
            return {
                "status": False,
                "message": f"Erro ao consultar API: {data.get('message')}",
            }

    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if r.status_code != 200:
        api_msg = data.get("message", "API retornou erro")
        return {
            "status": False,
            "message": _friendly_api_limit_message(str(api_msg)),
            "response": data,
        }

    subusers = data.get("subusers", [])

    if not subusers:
        print("Nenhum usuário encontrado")
        return {
            "status": False,
            "message": _friendly_api_limit_message(data.get("message", "Nenhum usuário encontrado")),
            "response": data
        }

    _SUBUSER_LIST_CACHE["at"] = now
    _SUBUSER_LIST_CACHE["users"] = subusers

    return {
        "status": True,
        "message": "Usuários encontrados com sucesso",
        "users": subusers
    }


def _normalize_subuser_row(raw: dict | None) -> dict | None:
    if not isinstance(raw, dict):
        return None
    nested = raw.get("user") if isinstance(raw.get("user"), dict) else raw
    if not isinstance(nested, dict):
        return None
    uid = nested.get("id") or nested.get("subuser_id")
    login = nested.get("login")
    if uid is None or not login:
        return None
    password = nested.get("password")
    return {
        "id": int(uid),
        "login": str(login).strip(),
        "password": password if password is not None else "",
    }


def authenticate_subuser_by_login(login: str, password: str) -> dict:
    """
    Valida sub-usuário Proxy Private sem listar todos na API quando possível.
    1) painel_subusers_local + GET /sub-user/get (1 chamada)
    2) fallback: lista em cache (máx. 1 listagem a cada 2 min)
    """
    from app.service.segury import issue_token

    login_s = (login or "").strip()
    if not login_s:
        return {"status": False, "message": "Informe o usuário da credencial"}

    local = get_subuser_local_by_login(login_s)
    if local.get("status") and local.get("row"):
        ext_id = local["row"].get("external_subuser_id")
        try:
            sub_id = int(str(ext_id).strip())
        except (TypeError, ValueError):
            sub_id = None
        if sub_id is not None:
            api = get_user_by_id(sub_id)
            if api.get("status"):
                row = _normalize_subuser_row(api.get("user") or api)
                if row and row["login"] == login_s and row["password"] == password:
                    token = issue_token(row["id"])
                    return {
                        "status": True,
                        "message": "Login realizado com sucesso",
                        "role": "subuser",
                        "token": token,
                    }

    data = get_all_user(use_cache=True)
    if not data["status"]:
        return {
            "status": False,
            "message": data.get("message", "Erro ao consultar API da proxy"),
        }

    for user in data.get("users") or []:
        if not isinstance(user, dict):
            continue
        if user.get("login") == login_s and user.get("password") == password:
            uid = user.get("id")
            if uid is None:
                continue
            token = issue_token(int(uid))
            return {
                "status": True,
                "message": "Login realizado com sucesso",
                "role": "subuser",
                "token": token,
            }

    return {"status": False, "message": "Credencial inválida"}


def _build_proxy_credential(hostname: str, port: int, login: str, password: str) -> str | None:
    login = (login or "").strip()
    password = password if password is not None else ""
    host = (hostname or "").strip()
    if not host or not login:
        return None
    return f"{host}:{int(port)}:{login}:{password}"


def _balance_fields_from_api(balance_res: dict | None) -> dict:
    if not balance_res or not balance_res.get("status"):
        return {
            "balance_ok": False,
            "balance_error": (balance_res or {}).get("message"),
        }
    raw = balance_res.get("data")
    if not isinstance(raw, dict):
        return {"balance_ok": False, "balance_error": "Resposta de saldo inválida"}

    def _num(key: str):
        v = raw.get(key)
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    total_b = _num("balance_total")
    avail_b = _num("balance")
    used_b = _num("balance_used")

    return {
        "balance_ok": True,
        "balance_available": avail_b,
        "balance_available_format": raw.get("balance_format"),
        "balance_used": used_b,
        "balance_used_format": raw.get("balance_used_format"),
        "balance_total": total_b,
        "balance_total_format": raw.get("balance_total_format"),
        "threads_used": raw.get("threads_used"),
    }


def _serialize_subuser_admin_row(
    raw: dict,
    *,
    proxy_hosts: list[str],
    proxy_port: int,
    balance_res: dict | None,
    local_row: dict | None,
) -> dict:
    uid = raw.get("id")
    login = str(raw.get("login") or (local_row or {}).get("login") or "").strip()
    password = raw.get("password")
    if password is None:
        password = ""
    else:
        password = str(password)

    hosts = [h for h in proxy_hosts if h] or ["painel.local"]
    primary = hosts[0]
    credentials = []
    for h in hosts:
        cred = _build_proxy_credential(h, proxy_port, login, password)
        if cred:
            credentials.append({"hostname": h, "credential": cred})

    row = {
        "id": uid,
        "login": login or None,
        "password": password or None,
        "label": raw.get("label") or (local_row or {}).get("label"),
        "threads": raw.get("threads"),
        "blocked": bool(raw.get("blocked")),
        "proxy_host": primary,
        "proxy_port": int(proxy_port),
        "proxy_hosts": hosts,
        "credential": _build_proxy_credential(primary, proxy_port, login, password),
        "credentials": credentials,
        "local_limite_gb": (local_row or {}).get("limite_gb"),
        "criado_por": (local_row or {}).get("criado_por"),
    }
    row.update(_balance_fields_from_api(balance_res))
    return row


def get_all_users_enriched_for_admin(*, proxy_port: int = 823, max_workers: int = 8) -> dict:
    """
    Lista sub-usuários com saldo (GB/MB), credencial proxy e dados para o painel admin.
    """
    base = get_all_user()
    if not base["status"]:
        return base

    from db.queires import get_proxy_hostnames_for_dashboard, list_subusers_local_map

    hosts_res = get_proxy_hostnames_for_dashboard()
    hosts: list[str] = []
    if hosts_res.get("status") and hosts_res.get("hosts"):
        hosts = [str(h).strip() for h in hosts_res["hosts"] if str(h).strip()]
    if not hosts:
        hosts = ["painel.local"]

    local_map = {}
    lm = list_subusers_local_map()
    if lm.get("status"):
        local_map = lm.get("map") or {}

    users_raw = base.get("users") or []
    if not users_raw:
        return {
            "status": True,
            "message": "Nenhum usuário na API",
            "users": [],
            "proxy_hosts": hosts,
            "proxy_port": int(proxy_port),
        }

    workers = max(1, min(int(max_workers), 12, len(users_raw)))

    def _one(raw: dict) -> dict:
        uid = raw.get("id")
        sid = str(uid) if uid is not None else ""
        bal = get_balance(sid) if sid else {"status": False, "message": "ID inválido"}
        local_row = local_map.get(sid)
        return _serialize_subuser_admin_row(
            raw,
            proxy_hosts=hosts,
            proxy_port=proxy_port,
            balance_res=bal,
            local_row=local_row,
        )

    enriched: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_one, u): u for u in users_raw}
        for fut in as_completed(futures):
            try:
                enriched.append(fut.result())
            except Exception as e:
                raw = futures[fut]
                enriched.append(
                    _serialize_subuser_admin_row(
                        raw,
                        proxy_hosts=hosts,
                        proxy_port=proxy_port,
                        balance_res={"status": False, "message": str(e)[:200]},
                        local_row=local_map.get(str(raw.get("id"))),
                    )
                )

    enriched.sort(key=lambda x: int(x.get("id") or 0))

    return {
        "status": True,
        "message": f"{len(enriched)} sub-usuário(s) com detalhes",
        "users": enriched,
        "proxy_hosts": hosts,
        "proxy_port": int(proxy_port),
    }


def get_user_by_id(id: int):
    params = {
        "subuser_id": id
    }
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/get"
    token = valid_token_and_generate_new_token()

    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, params=params, timeout=20, headers=headers)
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}"
        }
    try:
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    # Nem toda resposta 200 traz a chave "status"; evita KeyError
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Usuário encontrado com sucesso",
        "user": data,
    }


def get_history(user_id: str, limit: int = 50, offset: int = 0, period: str = "month") -> dict:
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/usage-stat/detail"
    params = {
        "subuser_id": str(user_id),
        "period": period,
        "limit": limit,
        "offset": offset
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, params=params, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Histórico consultado com sucesso",
        "data": data,
    }

def get_balance(user_id: str) -> dict:
    params = {
        "subuser_id": str(user_id)
    }
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/balance/get"
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, params=params, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Saldo consultado com sucesso",
        "data": data,
    }


def get_all_paises() -> dict:
    url = f"{ResellerBackendData.API_URL}/reseller/common/locations?pool_type=datacenter"
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    return {
        "status": True,
        "message": "Países consultados com sucesso",
        "data": data,
    }

def _normalize_paises_list(payload) -> list[dict]:
    """Extrai lista [{country_code, country_name}, ...] de respostas aninhadas da API."""
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict) and p.get("country_code")]
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("paises"), list):
        return _normalize_paises_list(payload["paises"])
    inner = payload.get("data")
    if inner is not None:
        return _normalize_paises_list(inner)
    return []


def get_all_paises_dict() -> dict:
    data = get_all_paises()
    if not data["status"]:
        return {
            "status": False,
            "message": data["message"]
        }
    paises = _normalize_paises_list(data.get("data"))
    if not paises:
        return {
            "status": False,
            "message": "Nenhum país retornado pela API",
            "response": data.get("data"),
        }
    return {
        "status": True,
        "message": "Países consultados com sucesso",
        "data": {
            "paises": paises
        }
    }

def get_pais_user(user_id: str) -> dict:
    from app.service.format import format_paises_user_dict
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/get"

    params = {
        "subuser_id": int(user_id)
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, params=params, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    
    pais = format_paises_user_dict(data)
    return {
        "status": True,
        "message": "País do usuário consultado com sucesso",
        "pais": pais,
    }


def normalize_country_codes(codes: list | None) -> list[str]:
    """Códigos ISO alpha-2 em minúsculas (ex.: br, us)."""
    if not codes:
        return []
    out: list[str] = []
    for item in codes:
        code = str(item).strip().lower()
        if len(code) == 2 and code.isalpha():
            out.append(code)
    return sorted(set(out))


def set_pais(user_id: int, pais: list[str]) -> dict:
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/set-default-pool-parameters"

    payload = {
        "subuser_id": int(user_id),
        "default_pool_parameters": {
            "countries": pais,
            "anonymous_filter": True,
            "rotation_interval": 60
        }
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.post(url, json=payload, timeout=20, headers=headers)
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}"
        }
    if r.status_code != 200:
        return {
            "status": False,
            "message": "API retornou erro",
            "response": r.json()
        }
    try:
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "País setado com sucesso",
        "data": data,
    }

def set_threads(user_id: str, threads: int | str | None) -> dict:
    if threads is None:
        return {
            "status": False,
            "message": "threads é obrigatório",
        }
    try:
        threads_n = int(threads)
    except (TypeError, ValueError):
        return {
            "status": False,
            "message": "threads deve ser um número inteiro",
        }
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return {
            "status": False,
            "message": "subuser_id inválido",
        }
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/update"
    payload = {
        "subuser_id": uid,
        "threads": threads_n,
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.post(url, json=payload, timeout=20, headers=headers)
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}"
        }
    if r.status_code != 200:
        return {
            "status": False,
            "message": "API retornou erro",
            "response": r.json()
        }
    try:
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Threads setadas com sucesso",
        "data": data,
    }


def set_protocolo_http_socks5(user_id: str, protocolo: list[str]) -> dict:
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/supported-protocols/set"
    payload = {
        "subuser_id": int(user_id),
        "supported_protocols": protocolo
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.post(url, json=payload, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Protocolo setado com sucesso",
        "data": data,
    }

def get_protocolo(user_id: str) -> dict:
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/supported-protocols/get"
    params = {
        "subuser_id": int(user_id)
    }
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {
            "status": False,
            "message": token["message"]
        }
    headers = {
        "Authorization": f"Bearer {token['token']}"
    }
    try:
        r = requests.get(url, params=params, timeout=20, headers=headers)
    except Exception as e:
        return {
            "status": False,
            "message": f"Erro ao consultar API: {e}"
        }
    if r.status_code != 200:
        return {
            "status": False,
            "message": "API retornou erro",
            "response": r.json()
        }
    try:
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro"),
            "response": data,
        }
    return {
        "status": True,
        "message": "Protocolo consultado com sucesso",
        "data": data,
    }


def _extract_subuser_id(payload: dict) -> int | None:
    """Extrai ID do sub-usuário em respostas variadas da API."""
    if not isinstance(payload, dict):
        return None
    for key in ("id", "subuser_id"):
        val = payload.get(key)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
    nested = payload.get("subuser")
    if isinstance(nested, dict):
        return _extract_subuser_id(nested)
    return None


def create_subuser(
    *,
    label: str,
    login: str,
    password: str,
    threads: int = 100,
    sticky_start: int = 11000,
    sticky_end: int = 20000,
) -> dict:
    """
    Cria sub-usuário na API DataImpulse (POST /reseller/sub-user/create).
    Mesmo formato de back-end/test/create_user.py.
    """
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {"status": False, "message": token["message"]}

    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/create"
    payload = {
        "token": token["token"],
        "label": (label or login).strip(),
        "login": login.strip(),
        "password": password,
        "sticky_range": {"start": int(sticky_start), "end": int(sticky_end)},
        "threads": int(threads),
    }

    try:
        r = requests.post(url, json=payload, timeout=30)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao criar sub-usuário: {e}"}

    if not isinstance(data, dict):
        return {"status": False, "message": "Resposta inválida da API", "response": data}
    if r.status_code != 200 or data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro ao criar sub-usuário"),
            "response": data,
        }

    subuser_id = _extract_subuser_id(data)
    return {
        "status": True,
        "message": "Sub-usuário criado na API",
        "subuser_id": subuser_id,
        "login": data.get("login") or login,
        "password": data.get("password") or password,
        "data": data,
    }


def add_subuser_balance(subuser_id: int, traffic_gb: float) -> dict:
    """
    Adiciona tráfego (GB) ao sub-usuário (POST /reseller/sub-user/balance/add).
    Mesmo formato de back-end/test/update_balance.py — campo traffic em GB.
    """
    try:
        traffic = float(traffic_gb)
    except (TypeError, ValueError):
        return {"status": False, "message": "traffic_gb inválido"}

    if traffic <= 0:
        return {"status": False, "message": "Informe um valor de GB maior que zero"}

    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {"status": False, "message": token["message"]}

    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/balance/add"
    payload = {
        "token": token["token"],
        "subuser_id": int(subuser_id),
        "traffic": traffic,
    }

    try:
        r = requests.post(url, json=payload, timeout=30)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao adicionar saldo: {e}"}

    if not isinstance(data, dict):
        return {"status": False, "message": "Resposta inválida da API", "response": data}
    if r.status_code != 200 or data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro ao adicionar saldo"),
            "response": data,
        }

    return {
        "status": True,
        "message": f"{traffic:g} GB adicionados ao sub-usuário",
        "data": data,
    }


def create_subuser_with_balance(
    *,
    label: str,
    traffic_gb: float,
    login: str | None = None,
    password: str | None = None,
    threads: int = 100,
    user_random: bool = True,
    criado_por: str | None = None,
    countries: list[str] | None = None,
) -> dict:
    """Cria sub-usuário e já credita GB (create + balance/add)."""
    from app.service.gerar_user_aleatorio import gerar_user_aleatorio

    label_v = (label or "").strip()
    if not label_v:
        return {"status": False, "message": "label é obrigatório"}

    try:
        traffic = float(traffic_gb)
    except (TypeError, ValueError):
        return {"status": False, "message": "traffic_gb inválido"}
    if traffic <= 0:
        return {"status": False, "message": "Informe a quantidade de GB (maior que zero)"}

    login_v = (login or "").strip() if login else ""
    password_v = password or ""
    if user_random or not login_v:
        login_v = gerar_user_aleatorio(16)
        password_v = gerar_user_aleatorio(24)
    elif not password_v:
        return {"status": False, "message": "password é obrigatório quando login é manual"}

    created = create_subuser(
        label=label_v,
        login=login_v,
        password=password_v,
        threads=threads,
    )
    if not created["status"]:
        return created

    subuser_id = created.get("subuser_id")
    if subuser_id is None:
        subuser_id = _extract_subuser_id(created.get("data") or {})

    if subuser_id is None:
        return {
            "status": False,
            "message": "Sub-usuário criado, mas a API não retornou o ID para creditar GB",
            "login": created.get("login"),
            "password": created.get("password"),
            "response": created.get("data"),
        }

    balance = add_subuser_balance(int(subuser_id), traffic)
    if not balance["status"]:
        return {
            "status": False,
            "message": f"Conta criada (id={subuser_id}), mas falha ao adicionar GB: {balance['message']}",
            "subuser_id": subuser_id,
            "login": created.get("login"),
            "password": created.get("password"),
            "partial": True,
        }

    login_out = str(created.get("login") or login_v)
    password_out = str(created.get("password") or password_v)

    try:
        from db.queires import insert_subuser_local

        insert_subuser_local(
            external_subuser_id=str(subuser_id),
            login=login_out,
            label=label_v,
            criado_por=criado_por,
            limite_gb=traffic,
        )
    except Exception:
        pass

    out = {
        "status": True,
        "message": f"Sub-usuário criado com {traffic:g} GB de saldo",
        "subuser_id": int(subuser_id),
        "login": login_out,
        "password": password_out,
        "label": label_v,
        "traffic_gb": traffic,
        "threads": threads,
    }

    block_res = ensure_subuser_has_panel_blocked_hosts(int(subuser_id))
    if block_res.get("status") and not block_res.get("unchanged") and not block_res.get("skipped"):
        out["blocked_hosts_applied"] = block_res.get("blocked_hosts")
    elif not block_res.get("status"):
        out["blocked_hosts_warning"] = block_res.get("message", "Falha ao aplicar hosts bloqueados")

    countries_norm = normalize_country_codes(countries)
    if countries_norm:
        pais_res = set_pais(int(subuser_id), countries_norm)
        if pais_res.get("status"):
            out["countries"] = countries_norm
        else:
            out["countries_warning"] = pais_res.get("message", "Falha ao definir países do pool")

    return out


BATCH_SUBUSER_MAX = 50


def create_subusers_batch_with_balance(
    *,
    label: str,
    traffic_gb: float,
    quantity: int = 1,
    threads: int = 100,
    criado_por: str | None = None,
    countries: list[str] | None = None,
) -> dict:
    """Cria N sub-usuários (cada um com login/senha aleatórios e saldo GB)."""
    label_v = (label or "").strip()
    if not label_v:
        return {"status": False, "message": "label é obrigatório"}

    try:
        qty = int(quantity)
    except (TypeError, ValueError):
        return {"status": False, "message": "quantity inválido"}
    if qty < 1:
        return {"status": False, "message": "quantity deve ser pelo menos 1"}
    if qty > BATCH_SUBUSER_MAX:
        return {
            "status": False,
            "message": f"Máximo de {BATCH_SUBUSER_MAX} contas por vez",
        }

    try:
        traffic = float(traffic_gb)
    except (TypeError, ValueError):
        return {"status": False, "message": "traffic_gb inválido"}
    if traffic <= 0:
        return {"status": False, "message": "Informe a quantidade de GB (maior que zero)"}

    created: list[dict] = []
    failed: list[dict] = []

    for index in range(1, qty + 1):
        item_label = f"{label_v} #{index}" if qty > 1 else label_v
        result = create_subuser_with_balance(
            label=item_label,
            traffic_gb=traffic,
            threads=threads,
            user_random=True,
            criado_por=criado_por,
            countries=countries,
        )
        if result.get("status"):
            created.append(result)
        else:
            failed.append({
                "index": index,
                "label": item_label,
                "message": result.get("message", "Erro desconhecido"),
                "partial": bool(result.get("partial")),
                "login": result.get("login"),
            })

    total = qty
    ok_count = len(created)
    if ok_count == 0:
        return {
            "status": False,
            "message": "Nenhuma conta foi criada",
            "created": created,
            "failed": failed,
            "quantity_requested": total,
            "quantity_created": 0,
        }

    if failed:
        message = f"{ok_count} de {total} contas criadas ({len(failed)} falha(s))"
    else:
        message = f"{ok_count} conta(s) criada(s) com {traffic:g} GB cada"

    return {
        "status": True,
        "message": message,
        "created": created,
        "failed": failed,
        "quantity_requested": total,
        "quantity_created": ok_count,
    }

def get_panel_blocked_hostnames() -> list[str]:
    """Hosts ativos cadastrados no painel (painel_blocked_hosts)."""
    from db.queries_blocked_hosts import get_active_blocked_hostnames

    res = get_active_blocked_hostnames()
    if not res.get("status"):
        return []
    return list(res.get("hosts") or [])


def get_all_panel_blocked_hostnames_registered() -> list[str]:
    """Todos os domínios já cadastrados no painel (ativos ou inativos)."""
    from db.queries_blocked_hosts import get_all_panel_blocked_hostnames

    res = get_all_panel_blocked_hostnames()
    if not res.get("status"):
        return []
    return list(res.get("hosts") or [])


def compute_subuser_blocked_hosts_target(
    current: list | None,
    *,
    force_remove: list[str] | None = None,
) -> list[str]:
    """
    Lista final na API: hosts ativos do painel + extras que o próprio usuário adicionou.
    Domínios que saíram do painel (removidos/desativados no admin) são retirados da API.
    """
    panel_active = set(get_panel_blocked_hostnames())
    all_panel = set(get_all_panel_blocked_hostnames_registered())
    current_set = set(_normalize_blocked_host_list(current))
    if force_remove:
        current_set -= set(_normalize_blocked_host_list(force_remove))
    user_custom = current_set - all_panel
    return sorted(panel_active | user_custom)


def _normalize_blocked_host_list(hosts: list | None) -> list[str]:
    from db.queries_blocked_hosts import _normalize_blocked_hostname

    out: list[str] = []
    for item in hosts or []:
        try:
            out.append(_normalize_blocked_hostname(str(item)))
        except ValueError:
            continue
    return sorted(set(out))


def sanitize_client_blocked_hosts(requested: list | None) -> list[str]:
    """Lista final para o cliente: inclui sempre os hosts protegidos do painel."""
    panel = set(get_panel_blocked_hostnames())
    return sorted(set(_normalize_blocked_host_list(requested)) | panel)


def block_hosts_subuser(subuser_id: int, blocked_hosts: list[str]) -> dict:
    """Define hosts bloqueados (POST /reseller/sub-user/set-blocked-hosts)."""
    token = valid_token_and_generate_new_token()
    if not token["status"]:
        return {"status": False, "message": token["message"]}

    hosts = _normalize_blocked_host_list(blocked_hosts)
    url = f"{ResellerBackendData.API_URL}/reseller/sub-user/set-blocked-hosts"
    payload = {
        "subuser_id": int(subuser_id),
        "blocked_hosts": hosts,
    }
    headers = {
        "Authorization": f"Bearer {token['token']}",
    }
    try:
        r = requests.post(url, json=payload, timeout=20, headers=headers)
        data = r.json()
    except ValueError:
        return {
            "status": False,
            "message": "Resposta da API não é JSON válido",
            "response": r.text,
        }
    except Exception as e:
        return {"status": False, "message": f"Erro ao bloquear hosts: {e}"}

    if not isinstance(data, dict):
        return {
            "status": False,
            "message": "Resposta inválida da API",
            "response": data,
        }
    if r.status_code not in (200, 201) or data.get("status") is False:
        return {
            "status": False,
            "message": data.get("message", "API retornou erro ao bloquear hosts"),
            "response": data,
        }

    applied = data.get("blocked_hosts")
    if not isinstance(applied, list):
        applied = hosts

    return {
        "status": True,
        "message": "Hosts bloqueados atualizados",
        "blocked_hosts": applied,
        "response": data,
    }


def sync_subuser_blocked_hosts(
    subuser_id: int,
    *,
    force_remove: list[str] | None = None,
) -> dict:
    """Alinha blocked_hosts na API com o painel (adiciona e remove conforme o banco)."""
    user_res = get_user_by_id(int(subuser_id))
    if not user_res.get("status"):
        return user_res

    current = _normalize_blocked_host_list((user_res.get("user") or {}).get("blocked_hosts"))
    target = compute_subuser_blocked_hosts_target(current, force_remove=force_remove)

    if set(current) == set(target):
        return {
            "status": True,
            "message": "Hosts bloqueados já sincronizados",
            "unchanged": True,
            "blocked_hosts": target,
        }

    result = block_hosts_subuser(int(subuser_id), target)
    if result.get("status"):
        result["unchanged"] = False
        result["blocked_hosts"] = result.get("blocked_hosts") or target
    return result


def ensure_subuser_has_panel_blocked_hosts(subuser_id: int) -> dict:
    """Compat: garante alinhamento completo com o painel."""
    return sync_subuser_blocked_hosts(int(subuser_id))


def get_client_blocked_hosts_payload(subuser_id: int) -> dict:
    """Lista hosts bloqueados do sub-usuário com origem (painel vs usuário)."""
    user_res = get_user_by_id(int(subuser_id))
    if not user_res.get("status"):
        return user_res

    panel_active = set(get_panel_blocked_hostnames())
    all_panel = set(get_all_panel_blocked_hostnames_registered())
    current = _normalize_blocked_host_list((user_res.get("user") or {}).get("blocked_hosts"))
    user_only = sorted(set(current) - all_panel)

    entries = [
        {
            "hostname": host,
            "protected": host in panel_active,
            "source": "panel" if host in panel_active else "user",
        }
        for host in current
    ]

    return {
        "status": True,
        "message": "Hosts bloqueados carregados",
        "blocked_hosts": current,
        "panel_hosts": sorted(panel_active),
        "user_hosts": user_only,
        "hosts": entries,
    }


def add_client_blocked_host(subuser_id: int, hostname: str) -> dict:
    """Cliente adiciona domínio à lista de bloqueio (mantém hosts do painel)."""
    from db.queries_blocked_hosts import _normalize_blocked_hostname

    try:
        new_host = _normalize_blocked_hostname(hostname)
    except ValueError as e:
        return {"status": False, "message": str(e)}

    view = get_client_blocked_hosts_payload(int(subuser_id))
    if not view.get("status"):
        return view

    current = list(view.get("blocked_hosts") or [])
    if new_host in current:
        return {
            "status": True,
            "message": "Domínio já está bloqueado",
            "blocked_hosts": current,
            **{k: view[k] for k in ("panel_hosts", "user_hosts", "hosts") if k in view},
        }

    target = sanitize_client_blocked_hosts(current + [new_host])
    result = block_hosts_subuser(int(subuser_id), target)
    if not result.get("status"):
        return result

    return get_client_blocked_hosts_payload(int(subuser_id))


def remove_client_blocked_host(subuser_id: int, hostname: str) -> dict:
    """Cliente remove domínio que ele mesmo adicionou (não remove hosts do painel)."""
    from db.queries_blocked_hosts import _normalize_blocked_hostname

    try:
        host = _normalize_blocked_hostname(hostname)
    except ValueError as e:
        return {"status": False, "message": str(e)}

    panel = set(get_panel_blocked_hostnames())
    if host in panel:
        return {
            "status": False,
            "message": "Este domínio é bloqueado pelo painel e não pode ser removido",
        }

    view = get_client_blocked_hosts_payload(int(subuser_id))
    if not view.get("status"):
        return view

    current = list(view.get("blocked_hosts") or [])
    if host not in current:
        return {"status": False, "message": "Domínio não está na sua lista de bloqueio"}

    remaining_user = [h for h in current if h != host]
    target = sanitize_client_blocked_hosts(remaining_user)
    result = block_hosts_subuser(int(subuser_id), target)
    if not result.get("status"):
        return result

    refreshed = get_client_blocked_hosts_payload(int(subuser_id))
    if refreshed.get("status"):
        refreshed["message"] = "Domínio removido do bloqueio"
    return refreshed


def _blocked_hosts_bulk_result(
    *,
    hostname: str,
    action: str,
    updated: int,
    unchanged: int,
    failed: list[dict],
    total: int,
) -> dict:
    fail_n = len(failed)
    return {
        "status": True,
        "message": (
            f"Domínio {hostname}: {action} em {updated} conta(s)"
            + (f", {unchanged} já estavam corretas" if unchanged else "")
            + (f", {fail_n} falha(s)" if fail_n else "")
        ),
        "hostname": hostname,
        "updated": updated,
        "unchanged": unchanged,
        "failed": failed,
        "total": total,
    }


def apply_blocked_hostname_to_all_subusers(hostname: str) -> dict:
    """Adiciona um domínio ao bloqueio de todos os sub-usuários na API."""
    from db.queries_blocked_hosts import _normalize_blocked_hostname

    try:
        host = _normalize_blocked_hostname(hostname)
    except ValueError as e:
        return {"status": False, "message": str(e)}

    users_res = get_all_user()
    if not users_res.get("status"):
        return users_res

    subusers = users_res.get("users") or []
    updated = 0
    unchanged = 0
    failed: list[dict] = []

    for row in subusers:
        uid = row.get("id")
        if uid is None:
            continue
        user_res = get_user_by_id(int(uid))
        if not user_res.get("status"):
            failed.append({
                "id": uid,
                "login": row.get("login"),
                "message": user_res.get("message", "Erro ao consultar usuário"),
            })
            continue

        current = _normalize_blocked_host_list((user_res.get("user") or {}).get("blocked_hosts"))
        if host in current:
            unchanged += 1
            continue

        target = sorted(set(current) | {host})
        result = block_hosts_subuser(int(uid), target)
        if not result.get("status"):
            failed.append({
                "id": uid,
                "login": row.get("login"),
                "message": result.get("message", "Erro ao bloquear host"),
            })
            continue
        updated += 1

    return _blocked_hosts_bulk_result(
        hostname=host,
        action="bloqueado",
        updated=updated,
        unchanged=unchanged,
        failed=failed,
        total=len(subusers),
    )


def remove_blocked_hostname_from_all_subusers(hostname: str) -> dict:
    """Remove um domínio do bloqueio de todos os sub-usuários na API."""
    from db.queries_blocked_hosts import _normalize_blocked_hostname

    try:
        host = _normalize_blocked_hostname(hostname)
    except ValueError as e:
        return {"status": False, "message": str(e)}

    users_res = get_all_user()
    if not users_res.get("status"):
        return users_res

    subusers = users_res.get("users") or []
    updated = 0
    unchanged = 0
    failed: list[dict] = []

    for row in subusers:
        uid = row.get("id")
        if uid is None:
            continue
        user_res = get_user_by_id(int(uid))
        if not user_res.get("status"):
            failed.append({
                "id": uid,
                "login": row.get("login"),
                "message": user_res.get("message", "Erro ao consultar usuário"),
            })
            continue

        current = _normalize_blocked_host_list((user_res.get("user") or {}).get("blocked_hosts"))
        if host not in current:
            unchanged += 1
            continue

        target = compute_subuser_blocked_hosts_target(current, force_remove=[host])
        result = block_hosts_subuser(int(uid), target)
        if not result.get("status"):
            failed.append({
                "id": uid,
                "login": row.get("login"),
                "message": result.get("message", "Erro ao remover bloqueio"),
            })
            continue
        updated += 1

    return _blocked_hosts_bulk_result(
        hostname=host,
        action="desbloqueado",
        updated=updated,
        unchanged=unchanged,
        failed=failed,
        total=len(subusers),
    )


def sync_all_subusers_panel_blocked_hosts(
    *,
    removed_hostnames: list[str] | None = None,
) -> dict:
    """Conferência geral: alinha todos os sub-usuários com a lista ativa do painel."""
    panel = get_panel_blocked_hostnames()
    force_remove = _normalize_blocked_host_list(removed_hostnames) if removed_hostnames else None
    users_res = get_all_user()
    if not users_res.get("status"):
        return users_res

    subusers = users_res.get("users") or []
    updated = 0
    unchanged = 0
    failed: list[dict] = []

    for row in subusers:
        uid = row.get("id")
        if uid is None:
            continue
        result = sync_subuser_blocked_hosts(int(uid), force_remove=force_remove)
        if not result.get("status"):
            failed.append({
                "id": uid,
                "login": row.get("login"),
                "message": result.get("message", "Erro desconhecido"),
            })
            continue
        if result.get("unchanged") or result.get("skipped"):
            unchanged += 1
        else:
            updated += 1

    fail_n = len(failed)
    return {
        "status": True,
        "message": (
            f"Conferência concluída: {updated} conta(s) ajustada(s), {unchanged} já corretas"
            + (f", {fail_n} falha(s)" if fail_n else "")
        ),
        "panel_blocked_hosts": panel,
        "updated": updated,
        "unchanged": unchanged,
        "failed": failed,
        "total": len(subusers),
    }
    