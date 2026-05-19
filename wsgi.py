"""Entrada WSGI para deploy na Vercel (Flask)."""
from __future__ import annotations

from load_env import load_project_env

load_project_env()

from app import create_app

app = create_app()
