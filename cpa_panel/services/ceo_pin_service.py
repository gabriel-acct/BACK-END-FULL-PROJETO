"""PIN para ações sensíveis na ARE CEO (marcar conta paga, valor extra no total).

Defina ``PAINEL_CEO_ACAO_PIN`` no ambiente para alterar; padrão ``202026``."""
from __future__ import annotations

import hmac
import os

_DEFAULT_PIN = "202026"


def _normalize_env_pin(raw: str | None) -> str | None:
    if not isinstance(raw, str):
        return None
    t = raw.strip().strip('"').strip("'")
    return t or None


def expected_ceo_acao_pin() -> str:
    return _normalize_env_pin(os.environ.get("PAINEL_CEO_ACAO_PIN")) or _DEFAULT_PIN


def body_has_valid_ceo_pin(body: dict | None) -> bool:
    if not isinstance(body, dict):
        return False
    got = body.get("ceo_pin")
    if got is None and "ceo_pin" not in body:
        return False
    submitted = str(got).strip() if got is not None else ""
    expected = expected_ceo_acao_pin()
    try:
        return hmac.compare_digest(
            submitted.encode("utf-8"),
            expected.encode("utf-8"),
        )
    except Exception:
        return False
