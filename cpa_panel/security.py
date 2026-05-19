from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from flask import current_app


def _jwt_secret() -> str:
    return str(current_app.config.get("CPA_JWT_SECRET") or current_app.config["JWT_SECRET"])


def _jwt_alg() -> str:
    return str(current_app.config.get("CPA_JWT_ALG") or current_app.config.get("JWT_ALG") or "HS256")


def _jwt_expire_minutes() -> int:
    return int(current_app.config.get("CPA_JWT_EXPIRE_MINUTES") or current_app.config.get("JWT_EXPIRE_MINUTES") or 1440)


def issue_token(username: str, porta: int) -> str:
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=_jwt_expire_minutes())
    payload = {
        "sub": username,
        "porta": porta,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(
        payload,
        _jwt_secret(),
        algorithm=_jwt_alg(),
    )


def issue_impersonation_token(username: str, porta: int, imp_by_username: str) -> str:
    """Token de sessão equivalente ao login do usuário alvo; não reutilizar para admin."""
    now = datetime.now(UTC)
    minutes = int(
        current_app.config.get("CPA_JWT_IMPERSONATION_EXPIRE_MINUTES")
        or current_app.config.get("JWT_IMPERSONATION_EXPIRE_MINUTES")
        or 60
    )
    exp = now + timedelta(minutes=max(5, minutes))
    payload = {
        "sub": username,
        "porta": int(porta),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "imp": True,
        "imp_by": str(imp_by_username),
    }
    return jwt.encode(
        payload,
        _jwt_secret(),
        algorithm=_jwt_alg(),
    )


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        _jwt_secret(),
        algorithms=[_jwt_alg()],
    )


CEO_UNLOCK_EXPIRE_MINUTES = 20


class TokenInvalidError(Exception):
    pass


class CeoUnlockInvalidError(TokenInvalidError):
    pass


def issue_ceo_unlock_token(username: str) -> tuple[str, datetime]:
    """Token de desbloqueio da página ARE CEO (não é o PIN; TTL curto)."""
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=CEO_UNLOCK_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "ceo_unlock": True,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    tok = jwt.encode(
        payload,
        _jwt_secret(),
        algorithm=_jwt_alg(),
    )
    return tok, exp


def payload_from_ceo_unlock_token(raw: str) -> dict:
    if not raw or not str(raw).strip():
        raise CeoUnlockInvalidError("Sessão ARE CEO ausente")
    try:
        payload = decode_token(str(raw).strip())
    except jwt.PyJWTError as e:
        raise CeoUnlockInvalidError("Sessão ARE CEO expirada ou inválida") from e
    if not payload.get("ceo_unlock"):
        raise CeoUnlockInvalidError("Sessão ARE CEO inválida")
    return payload


def payload_from_authorization_header(auth_header: str | None) -> dict:
    if not auth_header or not auth_header.startswith("Bearer "):
        raise TokenInvalidError("Token ausente")
    raw = auth_header[7:].strip()
    if not raw:
        raise TokenInvalidError("Token ausente")
    try:
        return decode_token(raw)
    except jwt.PyJWTError as e:
        raise TokenInvalidError(str(e)) from e
