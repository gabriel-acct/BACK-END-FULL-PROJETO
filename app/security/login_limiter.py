"""Limite de tentativas de login por IP (proteção contra brute-force)."""
from __future__ import annotations

import time
from collections import defaultdict

_WINDOW_SEC = 300
_MAX_ATTEMPTS = 10
_LOCKOUT_SEC = 900

_lockouts: dict[str, float] = {}
_attempts: dict[str, list[float]] = defaultdict(list)


def client_key_from_request(req) -> str:
    forwarded = (req.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (req.remote_addr or "unknown")[:64]


def check_login_allowed(key: str) -> tuple[bool, str | None]:
    now = time.time()
    locked_until = _lockouts.get(key)
    if locked_until and now < locked_until:
        wait_min = max(1, int((locked_until - now) / 60))
        return False, f"Muitas tentativas de login. Aguarde cerca de {wait_min} minuto(s)."

    if locked_until and now >= locked_until:
        _lockouts.pop(key, None)
        _attempts.pop(key, None)

    recent = [t for t in _attempts[key] if now - t < _WINDOW_SEC]
    _attempts[key] = recent
    if len(recent) >= _MAX_ATTEMPTS:
        _lockouts[key] = now + _LOCKOUT_SEC
        return False, "Muitas tentativas de login. Aguarde 15 minutos e tente novamente."
    return True, None


def record_login_failure(key: str) -> None:
    _attempts[key].append(time.time())


def record_login_success(key: str) -> None:
    _attempts.pop(key, None)
    _lockouts.pop(key, None)
