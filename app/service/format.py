import re
from port import is_allowed_port

_AT_STYLE = re.compile(r"^([^:]+):(\d+)@([^:]+):(.*)$", re.DOTALL)

def format_data_sub_usuarios(data: dict) -> dict:
    data = data["users"]
    users = []
    for user in data:
        users.append({
            "id": user["id"],
            "login": user["login"],
            "password": user["password"]
        })
    return users


def parse_porta_usuario_senha(credential: str) -> tuple[int, str, str]:
    """
    Credencial no formato host:porta:usuario:senha ou host:porta@usuario:senha.
    O host não é validado contra o banco (apenas não pode ser vazio).
    No formato com dois-pontos, usa split com limite para permitir ':' na senha.
    """
    raw = credential.strip()
    if not raw:
        raise ValueError("Informe sua credencial")

    m = _AT_STYLE.match(raw)
    if m:
        host, porta_s, username, senha = m.group(1).strip(), m.group(2).strip(), m.group(3).strip(), m.group(4)
        if not host:
            raise ValueError("Host obrigatório no início da credencial")
        if not porta_s or not username:
            raise ValueError("Porta e usuário são obrigatórios")
        try:
            porta = int(porta_s)
        except ValueError as e:
            raise ValueError("Porta inválida") from e
        if not is_allowed_port(porta):
            raise ValueError("Porta deve ser 823 (proxy HTTP) ou 824 (proxy SOCKS5)")
        return porta, username, senha.strip()

    parts = raw.split(":", 3)
    if len(parts) != 4:
        raise ValueError(
            "Use host:porta:usuario:senha ou host:porta@usuario:senha "
            "(ex.: proxy.cpaproxys.shop:823:user:senha)"
        )
    host, porta_s, username, senha = parts
    host = host.strip()
    if not host:
        raise ValueError("Host obrigatório no início da credencial")
    username = username.strip()
    senha = senha.strip()
    if not porta_s or not username:
        raise ValueError("Porta e usuário são obrigatórios")
    try:
        porta = int(porta_s.strip())
    except ValueError as e:
        raise ValueError("Porta inválida") from e
    if not is_allowed_port(porta):
        raise ValueError("Porta deve ser 823 (proxy HTTP) ou 824 (proxy SOCKS5)")
    return porta, username, senha


def format_paises_user_dict(paises: list[dict]) -> dict:
    paise = paises["default_pool_parameters"]["countries"]
    return paise