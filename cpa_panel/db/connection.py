"""Conexão MySQL do painel CPA (banco separado do Proxy Private)."""
from __future__ import annotations

import os

import mysql.connector


def conexao_bd():
    host = os.environ.get("CPA_DB_HOST") or os.environ.get("DB_HOST")
    if not host:
        raise RuntimeError(
            "Configure CPA_DB_HOST (ou DB_HOST) no .env/env ou nas Environment Variables da Vercel"
        )
    pwd = os.environ.get("CPA_DB_PASSWORD") or os.environ.get("PASSWORD_BD")
    return mysql.connector.connect(
        host=host,
        port=int(os.environ.get("CPA_DB_PORT") or os.environ.get("PORT", "3306")),
        user=os.environ.get("CPA_DB_USER") or os.environ.get("USER_BD", "root"),
        password=pwd,
        database=os.environ.get("CPA_DB_NAME") or os.environ.get("BD_NAME", "sistema_de_proxys"),
    )
