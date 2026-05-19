from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from flask import current_app


def issue_token(user_id: int) -> str:
    """JWT para sub-usuário do painel (ID da API DataImpulse)."""
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=current_app.config["JWT_EXPIRE_MINUTES"])
    payload = {
        "sub": str(user_id),
        "role": "subuser",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALG"],
    )


def issue_admin_token(admin_id: int) -> str:
    """JWT para administrador (ID em painel_admin_users)."""
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=current_app.config["JWT_EXPIRE_MINUTES"])
    payload = {
        "sub": str(admin_id),
        "role": "admin",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALG"],
    )


def issue_impersonation_token(username: str, porta: int, imp_by_username: str) -> str:
    """Token de sessão equivalente ao login do usuário alvo; não reutilizar para admin."""
    now = datetime.now(UTC)
    minutes = int(current_app.config.get("JWT_IMPERSONATION_EXPIRE_MINUTES") or 60)
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
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALG"],
    )


def decode_token(token: str) -> dict:
    # Tokens legados podem ter "sub" numérico no JSON; PyJWT exige str se verify_sub=True
    payload = jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=[current_app.config["JWT_ALG"]],
        options={"verify_sub": False},
    )
    if payload.get("sub") is not None:
        payload["sub"] = str(payload["sub"])
    return payload


class TokenInvalidError(Exception):
    pass


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
