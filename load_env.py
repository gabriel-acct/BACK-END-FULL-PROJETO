"""Carrega variáveis de ambiente do back-end (.env nesta pasta ou na raiz do repo)."""
from __future__ import annotations

import os
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent


def _load_env_file_manual(path: Path) -> None:
    """Fallback sem python-dotenv (ex.: venv incompleto)."""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ[key] = val


def _load_env_file(path: Path) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(path, override=False)
    except ImportError:
        _load_env_file_manual(path)


def load_project_env() -> Path | None:
    """Prioridade: back-end/.env → back-end/env → raiz do repo (.env / env)."""
    for base in (BACKEND_ROOT, BACKEND_ROOT.parent):
        for name in (".env", "env"):
            path = base / name
            if path.is_file():
                _load_env_file(path)
                return path
    return None
