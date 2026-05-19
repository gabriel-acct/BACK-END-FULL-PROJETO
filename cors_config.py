"""Origens CORS para o app unificado (não usar origins='*' com credentials)."""
from __future__ import annotations

import os
import re

from load_env import load_project_env

load_project_env()


def cors_origin_patterns() -> list[str | re.Pattern[str]]:
    raw = (os.getenv("WEB_CORS_ORIGINS") or "").strip()
    origins: list[str | re.Pattern[str]] = []
    if raw:
        origins.extend(o.strip().rstrip("/") for o in raw.split(",") if o.strip())
    else:
        origins.extend(
            [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:4173",
                "http://127.0.0.1:4173",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]
        )
    site = (os.getenv("SITE_PUBLIC_URL") or "").strip().rstrip("/")
    if site and site not in origins:
        origins.append(site)

    # Dev: painel na LAN (ex.: http://192.168.x.x:5173) → API em :3001
    origins.append(re.compile(r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?$"))
    return origins
