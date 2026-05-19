"""Cálculo de subtotal/desconto/total na recarga por GB (mesma lógica no painel e na API)."""
from __future__ import annotations


def aplicar_desconto_recarga(gb: float, preco_por_gb: float, descontos: list[dict]) -> dict:
    """
    Entre as regras ativas com gb >= gb_minimo, aplica uma única regra:
    maior gb_minimo vence; empate: menor ordem; depois maior id.
    Desconto: percentual sobre subtotal OU valor fixo em R$ (nunca ambos na mesma linha).
    """
    gb = float(gb)
    preco_por_gb = float(preco_por_gb)
    subtotal = round(gb * preco_por_gb, 2)

    eligible: list[dict] = []
    for d in descontos:
        if not int(d.get("ativo", 1)):
            continue
        try:
            if gb >= float(d["gb_minimo"]):
                eligible.append(d)
        except (TypeError, ValueError):
            continue

    if not eligible:
        return {"subtotal": subtotal, "desconto_reais": 0.0, "total": subtotal, "regra": None}

    eligible.sort(
        key=lambda x: (
            -float(x["gb_minimo"]),
            int(x.get("ordem") or 0),
            -int(x["id"]),
        )
    )
    best = eligible[0]

    pct = best.get("percentual_desconto")
    fix = best.get("valor_fixo_reais")
    desconto = 0.0

    try:
        if pct is not None and float(pct) > 0:
            desconto = round(subtotal * float(pct) / 100.0, 2)
        elif fix is not None and float(fix) > 0:
            desconto = min(round(float(fix), 2), subtotal)
    except (TypeError, ValueError):
        desconto = 0.0

    total = round(max(0.0, subtotal - desconto), 2)

    regra: dict = {
        "id": int(best["id"]),
        "nome": str(best.get("nome") or ""),
        "gb_minimo": float(best["gb_minimo"]),
    }
    if pct is not None and float(pct) > 0:
        regra["percentual_desconto"] = float(pct)
    elif fix is not None and float(fix) > 0:
        regra["valor_fixo_reais"] = float(fix)

    return {"subtotal": subtotal, "desconto_reais": desconto, "total": total, "regra": regra}
