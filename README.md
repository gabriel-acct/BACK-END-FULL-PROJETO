# Back-end (API Flask)

API unificada: **Proxy Private** (`/api/v1`) + **CPA** (`/api`, `/api/admin`).

Projeto **autônomo** — deploy na Vercel com esta pasta como raiz do projeto.

## Estrutura

```
back-end/
  wsgi.py            # entrada Flask na Vercel
  pyproject.toml     # entrypoint para a Vercel
  vercel.json        # deploy só da API
  app/               # Proxy Private
  cpa_panel/         # CPA Proxy
  scripts/dev.sh     # servidor local
  requirements.txt
  .env               # você cria (não commitar)
```

## Desenvolvimento local

```bash
cd back-end
./scripts/install.sh
cp .env.example .env
./scripts/dev.sh
```

API: `http://127.0.0.1:3001` — health: `GET /api/health`

O **front-end** faz proxy de `/api` → esta porta em dev. Rode o front em outro terminal.

## Variáveis

Todas em **`back-end/.env`** (ver `.env.example`).

Em produção, use as mesmas chaves no painel da Vercel (não commite `.env`).

| Variável | Uso com front separado |
|----------|-------------------------|
| `WEB_CORS_ORIGINS` | URL do front (ex.: `https://app.seudominio.com`) |
| `SITE_PUBLIC_URL` | URL pública do front (links, webhooks exibidos) |

## Deploy (Vercel)

1. Novo projeto Vercel → **Root Directory**: `back-end` (se o repo for monorepo).
2. Framework: Flask (detecta `wsgi.py` + `requirements.txt` + `pyproject.toml`).
3. Variáveis de ambiente = conteúdo de `.env.example`.

Teste: `GET https://sua-api.vercel.app/api/health`
# BACK-END-FULL-PROJETO
