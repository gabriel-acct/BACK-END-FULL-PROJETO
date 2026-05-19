"""Intervalo de datas para filtros admin (parâmetros ?date_from=&date_to= em YYYY-MM-DD)."""
from __future__ import annotations

from datetime import datetime, timedelta


def parse_ymd(s: str | None) -> datetime | None:
    if s is None:
        return None
    t = str(s).strip()
    if not t:
        return None
    t = t[:10]
    try:
        return datetime.strptime(t, "%Y-%m-%d")
    except ValueError:
        return None


def normalize_day_range(
    date_from: str | None,
    date_to: str | None,
) -> tuple[datetime | None, datetime | None]:
    """
    Retorna (início inclusivo 00:00, fim exclusivo meia-noite do dia seguinte ao último dia).
    Assim SQL usa: col >= start AND col < end_exclusive.
    Se só uma data vier, filtra só esse dia.
    """
    a = parse_ymd(date_from)
    b = parse_ymd(date_to)
    if a and b and a > b:
        a, b = b, a
    start = a
    end_exclusive = (b + timedelta(days=1)) if b else None
    return start, end_exclusive
