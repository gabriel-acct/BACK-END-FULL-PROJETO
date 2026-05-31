# Revendedor (Sócio) — Proxy Private `/admin`

## Duas coisas diferentes (importante)

| O quê | Onde criar no menu | O que é |
|-------|-------------------|---------|
| **Revendedor** | **Equipe → Revendedores (equipe admin)** | Login no painel **separado** `/socio` (`host:porta:user:senha`). Cargo **Sócio / Revendedor** + **pool de GB**. |
| **Cliente (sub-usuário)** | **Equipe → Clientes API (criar)** | Conta na API DataImpulse que consome proxy. O revendedor cria **dentro do pool dele**. |

Sub-usuário **não vira** revendedor. Revendedor é **administrador** com cargo especial.

---

## Pré-requisito: SQL

No banco **`painel_reseller`** (não o CPA):

```bash
mysql -h HOST -u USER -p painel_reseller < back-end/sql/010_painel_admin_socio_revenda.sql
```

Sem isso, o cargo **Sócio / Revendedor** não aparece no formulário.

---

## Passo a passo (Dono)

1. Entre como **Dono** (`Administrador Principal` na visão geral).
2. Menu lateral **Equipe** → **Revendedores (equipe admin)**  
   (só o Dono vê este item; se não aparecer, você não está no cargo Dono).
3. Preencha usuário, senha, nome.
4. **Cargo:** `Sócio / Revendedor`
5. **Pool de GB:** ex. `500` (teto que ele pode distribuir).
6. **Criar administrador**.

Na lista abaixo, use **Editar** para alterar nome, e-mail, cargo, pool de GB, ativo ou senha.

O revendedor faz login em **`/socio`** (não use `/admin`). No painel dele: **Criar cliente** e **Meus clientes**; cada GB informado desconta do pool.

### URLs do revendedor

| URL | Função |
|-----|--------|
| `/socio` | Login exclusivo do revendedor |
| `/socio/painel` | Visão geral (pool GB) |
| `/socio/clientes/criar` | Criar cliente API |
| `/socio/clientes` | Listar clientes criados por ele |
| `/socio/marca` | Nome, logo e favicon para os seus clientes |
| `/socio/atividades` | Minhas atividades (auditoria só do revendedor) |
| `/socio/recarga` | Avisos de recarga PIX dos clientes dele |
| `/socio/hosts` | Hostnames de proxy (somente leitura) |
| `/socio/relatorio` | Resumo: pool, clientes, pedidos |

Sessão em `localStorage` separada (`painel_socio_token`). Dono/admin continuam em `/admin`.

Na tela de **login** (`/socio`) aparecem os cards com as áreas acima — equivalente ao menu de revendedor do CPA, **sem** área CEO / dono.

**Nota:** o módulo CPA usa `/painel-socio` (não `/socio`) para evitar conflito de rotas com este painel revendedor.

---

## Atalho na visão geral

Na **Visão geral**, card **Criar revendedor** (só Dono) abre a mesma tela.

---

## Auditoria

Todas as ações relevantes do revendedor vão para **Logs de auditoria** (`/admin` → Sistema), com `actor_username` = login do revendedor:

| Ação | Código |
|------|--------|
| Login no `/socio` | `socio.login` |
| Criar cliente | `subuser.create` / `subuser.create.batch` |
| Pool insuficiente (tentativa) | `subuser.create.denied` |
| Salvar marca | `socio.branding.update` |
| Logo / favicon | `socio.branding.logo`, etc. |
| Cliente entra no painel | `subuser.login` (registrado no revendedor) |

## Marca do revendedor (white-label)

Em **`/socio/marca`** o revendedor define nome, textos, logo e favicon.

- Só **sub-usuários com `criado_por` = username dele** recebem essa identidade no painel cliente (`GET /api/v1/branding?revendedor=...` ou automático após login do cliente).
- O site global do Dono (`/admin` → Identidade do site) **não** é alterado.

## SQL adicional

```bash
mysql -h HOST -u USER -p painel_reseller < back-end/sql/011_socio_branding_audit.sql
```

## API

- `GET /api/v1/admin/gb-pool` — pool do usuário logado
- `POST /api/v1/admin/admin-users` — body `limite_gb` obrigatório se `cargo` = socio
- `PATCH /api/v1/admin/admin-users/<id>` — editar conta (Dono)
- `GET/PATCH /api/v1/admin/socio-branding` — marca do revendedor logado
- `GET /api/v1/admin/socio/audit-logs` — auditoria filtrada pelo revendedor logado
- `GET /api/v1/admin/socio/recarga-pedidos` — pedidos PIX dos clientes `criado_por` = revendedor
- `GET /api/v1/admin/socio/report` — resumo operacional do revendedor
