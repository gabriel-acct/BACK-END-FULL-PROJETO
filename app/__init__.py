"""Aplicação Flask (entrada em back-end/api/index.py na Vercel)."""

from flask import Flask
from flask_cors import CORS
from config import Config
from cors_config import cors_origin_patterns


def create_app() -> Flask:
    """Cria a aplicação Flask."""
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(
        app,
        resources={r"/api/*": {"origins": cors_origin_patterns()}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Are-Ceo", "X-Ceo-Unlock"],
        methods=["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"],
    )

    @app.route("/")
    def index():
        return "API unificada — Proxy Private + CPA Proxy"

    from app.routes.api import api_bp
    from app.routes.admin import admin_bp
    from app.routes.webhooks_pushinpay import bp as webhooks_bp
    from cpa_panel import register_cpa_panel

    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(webhooks_bp)
    register_cpa_panel(app)

    return app