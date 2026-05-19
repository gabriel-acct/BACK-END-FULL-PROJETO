"""Integração do painel CPA Proxy no Flask principal (banco MySQL separado)."""

from __future__ import annotations

from flask import Flask

from cpa_panel.bootstrap import init_environment
from cpa_panel.config import Config as CpaConfig
from cpa_panel.http_errors import register_http_error_handlers


def register_cpa_panel(app: Flask) -> None:
    """Registra blueprints e config do módulo CPA no app unificado."""
    init_environment()

    for key in (
        "SECRET_KEY",
        "JWT_SECRET",
        "JWT_ALG",
        "JWT_EXPIRE_MINUTES",
        "JWT_IMPERSONATION_EXPIRE_MINUTES",
        "CORS_ORIGINS",
        "PUSHINPAY_API_BASE",
        "PUSHINPAY_API_TOKEN",
        "SITE_PUBLIC_URL",
        "PUSHINPAY_WEBHOOK_SECRET",
        "PUSHINPAY_WEBHOOK_HEADER",
        "PUSHINPAY_WEBHOOK_REQUIRE_SECRET",
        "RECARGA_PIX_MAX_PER_HOUR",
        "RECARGA_MAX_TOTAL_REAIS",
    ):
        if hasattr(CpaConfig, key):
            val = getattr(CpaConfig, key)
            cpa_key = f"CPA_{key}" if key in ("JWT_SECRET", "JWT_ALG", "JWT_EXPIRE_MINUTES", "JWT_IMPERSONATION_EXPIRE_MINUTES") else key
            if cpa_key.startswith("CPA_"):
                app.config[cpa_key] = val
            elif key not in app.config or app.config[key] is None:
                app.config[key] = val

    app.config.setdefault("CPA_JWT_SECRET", CpaConfig.JWT_SECRET)
    app.config.setdefault("CPA_JWT_ALG", CpaConfig.JWT_ALG)
    app.config.setdefault("CPA_JWT_EXPIRE_MINUTES", CpaConfig.JWT_EXPIRE_MINUTES)
    app.config.setdefault("CPA_JWT_IMPERSONATION_EXPIRE_MINUTES", CpaConfig.JWT_IMPERSONATION_EXPIRE_MINUTES)

    from cpa_panel.routes.admin_api import bp as cpa_admin_bp
    from cpa_panel.routes.api import bp as cpa_api_bp
    from cpa_panel.routes.webhooks_pushinpay import bp as cpa_webhooks_bp

    app.register_blueprint(cpa_api_bp)
    app.register_blueprint(cpa_admin_bp)
    app.register_blueprint(cpa_webhooks_bp)

    register_http_error_handlers(app)
