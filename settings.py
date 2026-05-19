import os

from load_env import load_project_env

load_project_env()

HOST = os.getenv("DB_HOST")
USER = os.getenv("DB_USER")
PORT = int(os.getenv("DB_PORT", 3306))
PASSWORD = os.getenv("DB_PASSWORD")
DB = os.getenv("DB_NAME")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", 60))


def require_db_config() -> None:
    missing = [k for k, v in (
        ("DB_HOST", HOST),
        ("DB_USER", USER),
        ("DB_PASSWORD", PASSWORD),
        ("DB_NAME", DB),
    ) if not v]
    if missing:
        raise RuntimeError(
            f"Configure no .env/env (local) ou nas Environment Variables da Vercel: {', '.join(missing)}"
        )
