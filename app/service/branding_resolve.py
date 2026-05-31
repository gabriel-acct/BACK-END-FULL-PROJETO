"""Resolve marca pública: site global + overlay do revendedor (sub-usuários dele)."""

from __future__ import annotations

from app.service.site_branding_public import branding_to_public_api


def get_revendedor_from_subuser_token(auth_header: str | None) -> str | None:
    """Se JWT for sub-usuário, retorna criado_por (username do revendedor)."""
    if not auth_header:
        return None
    try:
        from app.service.segury import payload_from_authorization_header, TokenInvalidError
        from db.queires import get_subuser_local_by_external_id

        payload = payload_from_authorization_header(auth_header)
        if payload.get("role") != "subuser":
            return None
        ext_id = str(payload.get("sub") or "").strip()
        if not ext_id:
            return None
        local = get_subuser_local_by_external_id(ext_id)
        if not local.get("status"):
            return None
        owner = str((local.get("row") or {}).get("criado_por") or "").strip()
        return owner or None
    except Exception:
        return None


def merge_branding_public(*, revendedor_username: str | None = None) -> dict:
    from db.queries_site_branding import get_site_branding
    from db.queries_socio_branding import get_socio_branding

    global_data = get_site_branding()
    if not global_data.get("status"):
        return global_data

    base = dict(global_data.get("branding") or {})
    owner = (revendedor_username or "").strip()

    if owner:
        socio_data = get_socio_branding(owner)
        if socio_data.get("status"):
            overlay = socio_data.get("branding") or {}
            for key, val in overlay.items():
                if val is None:
                    continue
                if isinstance(val, str) and not val.strip():
                    continue
                base[key] = val
            base["_revendedor"] = owner

    public = branding_to_public_api(base, socio_username=owner or None)
    return {"status": True, "branding": public, "revendedor": owner or None}
