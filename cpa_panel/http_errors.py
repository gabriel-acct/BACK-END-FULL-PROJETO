"""Handlers HTTP centralizados (404, 405, etc.)."""
from __future__ import annotations

from flask import Flask, jsonify, request


def register_http_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(_e):
        path = request.path
        payload = {"error": "Rota não encontrada", "path": path}
        return jsonify(payload), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "Método não permitido para esta rota"}), 405

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Erro interno: %s", e)
        detail = str(e) if app.debug else None
        payload: dict = {"error": "Erro interno no servidor"}
        if detail:
            payload["detail"] = detail[:500]
        return jsonify(payload), 500
