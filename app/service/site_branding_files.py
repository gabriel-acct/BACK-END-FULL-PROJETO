"""Upload e leitura de logo/favicon do painel."""

import os
import re
from pathlib import Path

ALLOWED_EXT = frozenset({".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico"})
MAX_BYTES = 2 * 1024 * 1024

_BRANDING_ROOT = Path(__file__).resolve().parents[2] / "uploads" / "branding"


def branding_dir() -> Path:
    _BRANDING_ROOT.mkdir(parents=True, exist_ok=True)
    return _BRANDING_ROOT


def safe_filename(kind: str, original: str) -> str:
    ext = Path(original or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        ext = ".png"
    base = "logo" if kind == "logo" else "favicon"
    return f"{base}{ext}"


def save_branding_file(kind: str, file_storage) -> dict:
    if not file_storage or not file_storage.filename:
        return {"status": False, "message": "Arquivo não enviado"}

    data = file_storage.read()
    if len(data) > MAX_BYTES:
        return {"status": False, "message": "Arquivo muito grande (máx. 2 MB)"}

    ext = Path(file_storage.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        return {
            "status": False,
            "message": "Formato inválido. Use PNG, JPG, WEBP, SVG ou ICO",
        }

    dest_dir = branding_dir()
    filename = safe_filename(kind, file_storage.filename)
    dest = dest_dir / filename

    for old in dest_dir.glob(f"{kind}.*"):
        if old.name != filename:
            try:
                old.unlink()
            except OSError:
                pass

    dest.write_bytes(data)
    return {"status": True, "message": "Arquivo salvo", "filename": filename}


def remove_branding_file(kind: str) -> dict:
    dest_dir = branding_dir()
    removed = False
    for f in dest_dir.glob(f"{kind}.*"):
        try:
            f.unlink()
            removed = True
        except OSError:
            pass
    if not removed:
        return {"status": True, "message": "Nenhum arquivo para remover", "filename": None}
    return {"status": True, "message": "Arquivo removido", "filename": None}


def resolve_branding_file(filename: str | None) -> Path | None:
    if not filename:
        return None
    if not re.match(r"^(logo|favicon)\.[a-z0-9]+$", filename, re.I):
        return None
    path = branding_dir() / filename
    if path.is_file():
        return path
    return None


def _safe_socio_username(username: str) -> str | None:
    u = (username or "").strip()
    if not u or not re.match(r"^[a-zA-Z0-9._-]{3,64}$", u):
        return None
    return u


def socio_branding_dir(admin_username: str) -> Path:
    safe = _safe_socio_username(admin_username)
    if not safe:
        raise ValueError("username inválido")
    dest = _BRANDING_ROOT / "socio" / safe
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def save_socio_branding_file(admin_username: str, kind: str, file_storage) -> dict:
    if not _safe_socio_username(admin_username):
        return {"status": False, "message": "Revendedor inválido"}
    if not file_storage or not file_storage.filename:
        return {"status": False, "message": "Arquivo não enviado"}

    data = file_storage.read()
    if len(data) > MAX_BYTES:
        return {"status": False, "message": "Arquivo muito grande (máx. 2 MB)"}

    ext = Path(file_storage.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        return {"status": False, "message": "Formato inválido. Use PNG, JPG, WEBP, SVG ou ICO"}

    dest_dir = socio_branding_dir(admin_username)
    filename = safe_filename(kind, file_storage.filename)
    dest = dest_dir / filename

    for old in dest_dir.glob(f"{kind}.*"):
        if old.name != filename:
            try:
                old.unlink()
            except OSError:
                pass

    dest.write_bytes(data)
    return {"status": True, "message": "Arquivo salvo", "filename": filename}


def remove_socio_branding_file(admin_username: str, kind: str) -> dict:
    if not _safe_socio_username(admin_username):
        return {"status": False, "message": "Revendedor inválido"}
    dest_dir = socio_branding_dir(admin_username)
    removed = False
    for f in dest_dir.glob(f"{kind}.*"):
        try:
            f.unlink()
            removed = True
        except OSError:
            pass
    if not removed:
        return {"status": True, "message": "Nenhum arquivo para remover", "filename": None}
    return {"status": True, "message": "Arquivo removido", "filename": None}


def resolve_socio_branding_file(admin_username: str, filename: str | None) -> Path | None:
    if not _safe_socio_username(admin_username) or not filename:
        return None
    if not re.match(r"^(logo|favicon)\.[a-z0-9]+$", filename, re.I):
        return None
    path = socio_branding_dir(admin_username) / filename
    if path.is_file():
        return path
    return None
