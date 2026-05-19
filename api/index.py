"""
Entrada serverless Vercel (projeto back-end).

Configure as variáveis no painel Vercel (mesmas de back-end/.env.example).
"""
from __future__ import annotations

from load_env import load_project_env

load_project_env()

from app import create_app

app = create_app()
