"""Regras de negócio da recarga PIX."""
from __future__ import annotations

import time
from collections import defaultdict
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from app.service.pushinpay_credentials import (
    effective_recarga_max_total_reais,
    effective_recarga_pix_max_per_hour,
)
from app.service.recarga_calc import aplicar_desconto_recarga
from db import queries_recarga as queries

_rate_bucket: dict[str, list[float]] = defaultdict(list)


def snap_gb(val: float, gb_min: float, gb_max: float, gb_step: float) -> float:
    step = float(gb_step) if gb_step and float(gb_step) > 0 else 1.0
    lo, hi = float(gb_min), float(gb_max)
    clamped = min(hi, max(lo, float(val)))
    n = round((clamped - lo) / step)
    x = lo + n * step
    x = min(hi, max(lo, x))
    return float(f"{x:.6f}")


def reais_para_centavos(valor_reais: Decimal | float | str) -> int:
    d = valor_reais if isinstance(valor_reais, Decimal) else Decimal(str(valor_reais))
    return int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def allow_pix_frequency(subuser_key: str) -> bool:
    """Limite por hora: banco (persistente) + memória (por processo)."""
    lim = int(effective_recarga_pix_max_per_hour())
    db_count = queries.count_pix_pedidos_recent_for_user(subuser_key, hours=1.0)
    if db_count >= lim:
        return False
    now = time.time()
    window = 3600.0
    bucket = _rate_bucket[subuser_key]
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= lim:
        return False
    bucket.append(now)
    return True


def calcular_cobranca_por_gb(gb_solicitado: float) -> tuple[dict[str, Any] | None, str | None]:
    cfg = queries.get_recarga_por_gb_config()
    disc_rows = queries.list_recarga_descontos_para_calculo()
    gb = snap_gb(gb_solicitado, cfg["gb_min"], cfg["gb_max"], cfg["gb_step"])

    if gb < cfg["gb_min"] or gb > cfg["gb_max"]:
        return None, "Quantidade de GB fora do intervalo permitido"

    sim = aplicar_desconto_recarga(gb, cfg["preco_por_gb_reais"], disc_rows)
    total = Decimal(str(sim["total"]))
    max_total = Decimal(str(effective_recarga_max_total_reais()))

    if total < Decimal("0.50"):
        return None, "Valor total abaixo do mínimo da operadora (R$ 0,50). Ajuste a quantidade de GB."

    if total > max_total:
        return None, "Valor total acima do limite permitido para uma única cobrança"

    cents = reais_para_centavos(total)
    if cents < 50:
        return None, "Valor em centavos abaixo do mínimo exigido pela PushinPay (50)"

    return {
        "modo": "por_gb",
        "preco_id": None,
        "gb_credito": gb,
        "valor_reais": float(total),
        "valor_centavos": cents,
        "simulacao": sim,
    }, None
