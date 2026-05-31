# Módulo Sócio (CPA Proxy)

Conta **sócio de topo** = cargo `socio`, `criado_por` vazio, `limite_gb` = pool total para revenda. Clientes do sócio têm `criado_por = username_do_socio` e a mesma porta de gateway (823/824).

## 1. Banco de dados (obrigatório uma vez)

No MySQL do CPA (`CPA_DB_NAME`, ex. `proxys_rotativas`):

```bash
cd back-end
python3 scripts/apply_socio_sql.py
```

Ou execute manualmente: `sql/cpa/INSTALL_socio_completo.sql`.

Arquivos granulares (mesmo conteúdo, em partes): `usuarios_proxy_criado_por.sql`, `painel_cargo_socio.sql`, `painel_socio_*.sql`, `painel_recarga_pedidos_pix_pushinpay_source.sql`.

## 2. Criar um sócio (Dono)

1. Login CPA: `host:porta:usuario:senha`
2. **Administração** → **Novo usuário**
3. Cargo: **Sócio**
4. **Limite (GB)** = pool (soma das cotas dos clientes não pode passar disso)
5. Porta: **823** (HTTP) ou **824** (SOCKS5) — os clientes do sócio herdam a mesma porta

## 3. O que o sócio vê no painel

Com cargo `socio` e migração aplicada:

| Menu | Função |
|------|--------|
| Meus clientes | Criar/listar clientes, alterar GB |
| Minhas atividades | Auditoria |
| Avisos recarga | PIX bloqueado por falta de pool |
| Hosts | Pedir hostnames (dono aprova na ARE CEO) |
| Relatório (sócio) | Pedidos PIX da rede |
| Configuração | Marca do menu + PushinPay do sócio |

## 4. Dono (ARE CEO)

- **Sócios & PIX global** — pool, PushinPay ativo, marca
- **Hosts dos sócios** — aprovar/rejeitar pedidos

O dono pode inspecionar a rede de um sócio com `?socio=username` nas APIs `/api/me/socio/*` (somente leitura).

## 5. Variáveis de ambiente

- `SITE_PUBLIC_URL` — URL do webhook PushinPay exibido ao sócio
- `PUSHINPAY_*` — conta global; o sócio pode cadastrar a própria em Configuração

## 6. API (referência)

- `GET /api/me` — `admin.socio_panel`, `socio_pool`, `socio_pushinpay`
- `GET|POST /api/me/socio/users`
- `GET /api/me/socio/audit-logs`, `/recarga-pedidos`, `/recarga-avisos`
- `GET|POST /api/me/socio/proxy-hosts`
- `GET|PATCH /api/me/pushinpay-socio`, `/me/panel-branding`
- `GET /api/admin/dono/socio-overview`, `/dono/socio-proxy-hosts`
