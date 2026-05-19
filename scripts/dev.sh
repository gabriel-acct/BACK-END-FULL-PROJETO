#!/usr/bin/env bash
# Sobe a API Flask local (porta 3001).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -x "${ROOT}/venv/bin/python3" ]]; then
  PY="${ROOT}/venv/bin/python3"
else
  PY="$(command -v python3)"
fi

cd "${ROOT}"
exec "${PY}" run_dev.py
