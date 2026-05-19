"""Carrega variáveis de ambiente do projeto (.env ou env na raiz)."""
from __future__ import annotations

from load_env import load_project_env


def init_environment() -> None:
    load_project_env()
