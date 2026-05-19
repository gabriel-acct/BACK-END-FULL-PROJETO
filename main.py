#!/usr/bin/env python3
"""
Único ponto de entrada do back-end.

- Vercel: usa a variável `app` (ver pyproject.toml → entrypoint = "main:app")
- Local:  python main.py   ou   ./scripts/dev.sh
"""
from __future__ import annotations

import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent
os.chdir(_BACKEND_DIR)
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from load_env import load_project_env

load_project_env()

from app import create_app

app = create_app()

DEV_PORT = int(os.getenv("FLASK_DEV_PORT", "3001"))


def _local_lan_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _api_health_ok(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


def _pick_free_port(start: int) -> int:
    for port in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    print(f"Erro: nenhuma porta livre entre {start} e {start + 19}.", file=sys.stderr)
    sys.exit(1)


def _run_dev_server() -> None:
    port = DEV_PORT

    if _port_open(port):
        if _api_health_ok(port):
            print("")
            print(f"  API já está rodando em http://127.0.0.1:{port}")
            print("  Não precisa iniciar de novo.")
            print("  No outro terminal:  cd front-end && npm run dev")
            print("")
            return
        print("")
        print(f"  Porta {port} está ocupada por outro programa.")
        print(f"  Encerre com:  fuser -k {port}/tcp")
        print(f"  Ou use outra porta:  FLASK_DEV_PORT=3002 python main.py")
        print("  (e no front-end/.env: VITE_DEV_API_PROXY=http://127.0.0.1:3002)")
        print("")
        sys.exit(1)

    port = _pick_free_port(port)
    if port != DEV_PORT:
        print(f"  Porta {DEV_PORT} ocupada; usando {port}.")
        print(f"  Defina no front-end/.env: VITE_DEV_API_PROXY=http://127.0.0.1:{port}")
        print("")

    lan = _local_lan_ip()
    print("")
    print("  API Flask (desenvolvimento)")
    print(f"  Nesta máquina:  http://127.0.0.1:{port}")
    if lan:
        print(f"  Outros na LAN:   http://{lan}:{port}")
    print("  No outro terminal: cd front-end && npm run dev")
    print("  (O Vite encaminha /api para esta porta.)")
    print("  Reinicie manualmente após alterar código Python.")
    print("")
    app.run(
        debug=True,
        host="0.0.0.0",
        port=port,
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    _run_dev_server()
