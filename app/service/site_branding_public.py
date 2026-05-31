"""Serialização pública da marca do site."""

from app.service.site_branding_files import resolve_branding_file


def branding_to_public_api(branding: dict, *, socio_username: str | None = None) -> dict:
    updated = branding.get("updated_at")
    version = ""
    if updated is not None:
        version = str(updated).replace(" ", "T")

    out = {
        "site_name": branding.get("site_name") or "Proxy Private",
        "site_tagline": branding.get("site_tagline"),
        "login_title": branding.get("login_title") or "Entrar na conta",
        "login_subtitle": branding.get("login_subtitle"),
        "footer_text": branding.get("footer_text"),
        "support_email": branding.get("support_email"),
        "support_whatsapp": branding.get("support_whatsapp"),
        "logo_url": None,
        "favicon_url": None,
    }

    link_logo = (branding.get("logo_url") or "").strip()
    if link_logo.lower().startswith(("http://", "https://")):
        out["logo_url"] = link_logo
    elif branding.get("logo_filename"):
        if socio_username:
            from app.service.site_branding_files import resolve_socio_branding_file

            if resolve_socio_branding_file(socio_username, branding["logo_filename"]):
                q = f"?v={version}" if version else ""
                enc = socio_username.replace("/", "_")
                out["logo_url"] = f"/api/v1/branding/socio/{enc}/logo{q}"
        elif resolve_branding_file(branding["logo_filename"]):
            q = f"?v={version}" if version else ""
            out["logo_url"] = f"/api/v1/branding/logo{q}"

    if branding.get("favicon_filename"):
        if socio_username:
            from app.service.site_branding_files import resolve_socio_branding_file

            if resolve_socio_branding_file(socio_username, branding["favicon_filename"]):
                q = f"?v={version}" if version else ""
                enc = socio_username.replace("/", "_")
                out["favicon_url"] = f"/api/v1/branding/socio/{enc}/favicon{q}"
        elif resolve_branding_file(branding["favicon_filename"]):
            q = f"?v={version}" if version else ""
            out["favicon_url"] = f"/api/v1/branding/favicon{q}"

    return out
