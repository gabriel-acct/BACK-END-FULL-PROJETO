"""Carrega variáveis de ambiente do back-end (.env nesta pasta)."""
from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parent


def load_project_env() -> Path | None:
    """Prioridade: `.env` → `env` na pasta do back-end."""
    for name in (".env", "env"):
        path = BACKEND_ROOT / name
        if path.is_file():
            load_dotenv(path, override=False)
            return path
    return None
