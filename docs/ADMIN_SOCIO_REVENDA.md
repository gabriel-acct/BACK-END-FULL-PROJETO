# Revendedor (Sócio) — Proxy Private `/admin`

Administradores com cargo **Sócio / Revendedor** podem criar sub-usuários na API, limitados ao **pool de GB** definido pelo Dono.

## Migração (banco `painel_reseller`)

```bash
mysql -h HOST -u USER -p painel_reseller < back-end/sql/010_painel_admin_socio_revenda.sql
```

## Criar revendedor (Dono)

1. **Equipe → Administradores**
2. Cargo: **Sócio / Revendedor**
3. **Pool de GB**: ex. `500` (teto total para distribuir)

## Comportamento

- Cada sub-usuário criado grava `limite_gb` em `painel_subusers_local` e `criado_por` = username do admin.
- Na criação: `quantidade × traffic_gb` não pode ultrapassar o **disponível** do pool.
- Lista de sub-usuários: o revendedor vê **apenas** contas que ele criou.
- Dono/administrador com bypass: sem limite de pool (comportamento anterior).

## API

- `GET /api/v1/admin/gb-pool` — resumo do pool do usuário logado
- `GET /api/v1/admin/summary` — inclui `gb_pool` quando aplicável
- `POST /api/v1/admin/admin-users` — body opcional `limite_gb` (obrigatório se cargo `socio`)
