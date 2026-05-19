from __future__ import annotations

import os


def _parse_origins(raw: str | None) -> list[str]:
    if not raw:
        return [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
            "https://proxy-rotativa-cpa.vercel.app",
            # Site em produção (front-end). Inclua aqui se não usar WEB_CORS_ORIGINS no ambiente.
            "https://www.cpaproxys.shop",
            "https://cpaproxys.shop",
        ]

    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "altere-em-producao-flask-secret")
    JWT_SECRET = os.getenv("SITE_JWT_SECRET", os.getenv("FLASK_SECRET_KEY", "troque-site-jwt-secret"))
    JWT_ALG = "HS256"
    JWT_EXPIRE_MINUTES = int(os.getenv("SITE_JWT_EXPIRE_MINUTES", "1440"))
    # Sessão «ver como usuário» (personificação) — mais curta que o login normal.
    JWT_IMPERSONATION_EXPIRE_MINUTES = int(os.getenv("SITE_JWT_IMPERSONATION_EXPIRE_MINUTES", "60"))
    CORS_ORIGINS = _parse_origins(os.getenv("WEB_CORS_ORIGINS"))

    # PushinPay (PIX) — nunca commitar token; use apenas variáveis de ambiente.
    # Sempre api.pushinpay.com.br — NÃO coloque aqui a URL do seu Flask/Vercel.
    PUSHINPAY_API_BASE = (os.getenv("PUSHINPAY_API_BASE") or "https://api.pushinpay.com.br/api").rstrip("/")
    PUSHINPAY_API_TOKEN = (os.getenv("PUSHINPAY_API_TOKEN") or "").strip()
    # URL pública do site (ex.: https://painel.seudominio.com) para montar o webhook.
    SITE_PUBLIC_URL = (os.getenv("SITE_PUBLIC_URL") or "").strip().rstrip("/")
    # Segredo enviado no header configurado no painel PushinPay (recomendado em produção).
    PUSHINPAY_WEBHOOK_SECRET = (os.getenv("PUSHINPAY_WEBHOOK_SECRET") or "").strip()
    PUSHINPAY_WEBHOOK_HEADER = (os.getenv("PUSHINPAY_WEBHOOK_HEADER") or "X-Webhook-Token").strip()
    # Se true, rejeita webhooks quando PUSHINPAY_WEBHOOK_SECRET não estiver definido.
    PUSHINPAY_WEBHOOK_REQUIRE_SECRET = os.getenv("PUSHINPAY_WEBHOOK_REQUIRE_SECRET", "1").strip() in (
        "1",
        "true",
        "yes",
    )
    RECARGA_PIX_MAX_PER_HOUR = int(os.getenv("RECARGA_PIX_MAX_PER_HOUR") or "30")
    RECARGA_MAX_TOTAL_REAIS = float(os.getenv("RECARGA_MAX_TOTAL_REAIS") or "50000")
