#!/usr/bin/env python3
"""
Aplica sql/cpa/INSTALL_socio_completo.sql no banco CPA (CPA_DB_* no .env).

Uso (a partir de back-end/):
  python3 scripts/apply_socio_sql.py
  python3 scripts/apply_socio_sql.py --dry-run
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from load_env import load_project_env

load_project_env()


def _conexao_bd():
    """Import direto de connection.py (evita carregar Flask via cpa_panel/__init__.py)."""
    import importlib.util

    path = _BACKEND / "cpa_panel" / "db" / "connection.py"
    spec = importlib.util.spec_from_file_location("cpa_db_connection", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Não foi possível carregar {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.conexao_bd()

SQL_FILE = _BACKEND / "sql" / "cpa" / "INSTALL_socio_completo.sql"

# MySQL: coluna/índice/tabela já existem
_IGNORE_ERRNO = frozenset({1050, 1060, 1061, 1062})


def _split_statements(sql: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip()
            if stmt:
                parts.append(stmt.rstrip(";").strip())
            buf = []
    tail = "\n".join(buf).strip()
    if tail:
        parts.append(tail.rstrip(";").strip())
    return [p for p in parts if p]


def main() -> int:
    parser = argparse.ArgumentParser(description="Migração CPA: módulo Sócio")
    parser.add_argument("--dry-run", action="store_true", help="Só lista os comandos SQL")
    args = parser.parse_args()

    if not SQL_FILE.is_file():
        print(f"Arquivo não encontrado: {SQL_FILE}", file=sys.stderr)
        return 1

    raw = SQL_FILE.read_text(encoding="utf-8")
    statements = _split_statements(raw)
    print(f"→ {len(statements)} comando(s) em {SQL_FILE.name}")

    if args.dry_run:
        for i, st in enumerate(statements, 1):
            preview = re.sub(r"\s+", " ", st)[:120]
            print(f"  {i}. {preview}…" if len(preview) >= 120 else f"  {i}. {preview}")
        return 0

    try:
        conn = _conexao_bd()
    except ImportError:
        print(
            "Dependência em falta. No venv do back-end execute:\n"
            "  pip install mysql-connector-python\n"
            "Ou rode:  ./scripts/install.sh",
            file=sys.stderr,
        )
        return 1
    except ModuleNotFoundError as e:
        if "mysql" in str(e).lower():
            print(
                "Instale mysql-connector-python no venv:\n"
                "  pip install mysql-connector-python",
                file=sys.stderr,
            )
            return 1
        raise
    cursor = conn.cursor()
    ok = 0
    skipped = 0
    failed = 0
    try:
        for i, st in enumerate(statements, 1):
            try:
                cursor.execute(st)
                conn.commit()
                ok += 1
                print(f"  OK  [{i}/{len(statements)}]")
            except Exception as e:
                errno = getattr(e, "errno", None)
                if errno in _IGNORE_ERRNO:
                    conn.rollback()
                    skipped += 1
                    print(f"  SKIP [{i}/{len(statements)}] (já aplicado: {e})")
                else:
                    conn.rollback()
                    failed += 1
                    print(f"  ERRO [{i}/{len(statements)}]: {e}", file=sys.stderr)
                    print(st[:500], file=sys.stderr)
        print(f"\nConcluído: {ok} ok, {skipped} ignorados, {failed} erro(s).")
        return 1 if failed else 0
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
