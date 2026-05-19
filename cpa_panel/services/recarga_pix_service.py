"""Regras de negócio da recarga PIX: validação, centavos, limite de frequência."""
from __future__ import annotations

import time
from collections import defaultdict
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from flask import current_app

from cpa_panel.db import queries
from cpa_panel.db.queries import _criado_por_str
from cpa_panel.services.pushinpay_credentials import effective_recarga_pix_max_per_hour
from cpa_panel.services.recarga_calc import aplicar_desconto_recarga

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
    cent = (d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(cent)


def allow_pix_frequency(username: str) -> bool:
    lim = int(effective_recarga_pix_max_per_hour())
    now = time.time()
    window = 3600.0
    bucket = _rate_bucket[username]
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= lim:
        return False
    bucket.append(now)
    return True


def calcular_cobranca_por_gb(gb_solicitado: float) -> tuple[dict[str, Any] | None, str | None]:
    """
    Recalcula subtotal/desconto/total no servidor (nunca confiar no front).
    Retorna (payload_ok, erro).
    """
    cfg = queries.get_recarga_por_gb_config()
    disc_rows = queries.list_recarga_descontos_para_calculo()
    gb = snap_gb(gb_solicitado, cfg["gb_min"], cfg["gb_max"], cfg["gb_step"])

    if gb < cfg["gb_min"] or gb > cfg["gb_max"]:
        return None, "Quantidade de GB fora do intervalo permitido"

    sim = aplicar_desconto_recarga(gb, cfg["preco_por_gb_reais"], disc_rows)
    total = Decimal(str(sim["total"]))
    max_total = Decimal(str(current_app.config.get("RECARGA_MAX_TOTAL_REAIS") or 50000))

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


def mensagem_recarga_bloqueada_pool_socio(user_row: dict | None, gb_credito: float) -> str | None:
    """
    Contas com `criado_por` só podem recarregar até o GB disponível no pool do sócio.
    Retorna mensagem de erro ou None se permitido.
    """
    if not user_row:
        return None
    cp = _criado_por_str(user_row)
    if not cp:
        return None
    d = queries.pool_disponivel_gb_socio(cp)
    g = float(gb_credito)
    if g <= d + 1e-6:
        return None
    return (
        f"Recarga não permitida: o pool do seu sócio tem apenas {d:.4f} GB livres para distribuir entre os clientes "
        f"(pedido de {g:.4f} GB). Reduza a quantidade ou peça ao sócio para aumentar o pool."
    )


def calcular_cobranca_preco_fixo(preco_id: int) -> tuple[dict[str, Any] | None, str | None]:
    row = queries.get_recarga_preco_ativo_by_id(int(preco_id))
    if not row:
        return None, "Plano de recarga inválido ou inativo"

    gb = float(row["gb_credito"])
    total = Decimal(str(row["preco_reais"]))
    max_total = Decimal(str(current_app.config.get("RECARGA_MAX_TOTAL_REAIS") or 50000))

    if total < Decimal("0.50"):
        return None, "Preço do plano abaixo do mínimo da operadora"

    if total > max_total:
        return None, "Valor do plano acima do limite configurado"

    cents = reais_para_centavos(total)
    if cents < 50:
        return None, "Valor em centavos abaixo do mínimo exigido pela PushinPay (50)"

    return {
        "modo": "preco_fixo",
        "preco_id": int(row["id"]),
        "gb_credito": gb,
        "valor_reais": float(total),
        "valor_centavos": cents,
        "simulacao": None,
    }, None


