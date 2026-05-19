#!/usr/bin/env bash
# Cria venv e instala dependências do back-end.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

if [[ ! -d venv ]]; then
  python3 -m venv venv
fi
./venv/bin/pip install -U pip
./venv/bin/pip install -r requirements.txt
echo ""
echo "  Pronto. Copie:  cp .env.example .env  e edite back-end/.env"
echo "  Suba a API:     ./scripts/dev.sh"
