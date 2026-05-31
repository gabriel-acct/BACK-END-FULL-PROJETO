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

Sessão em `localStorage` separada (`painel_socio_token`). Dono/admin continuam em `/admin`.

---

## Atalho na visão geral

Na **Visão geral**, card **Criar revendedor** (só Dono) abre a mesma tela.

---

## API

- `GET /api/v1/admin/gb-pool` — pool do usuário logado
- `POST /api/v1/admin/admin-users` — body `limite_gb` obrigatório se `cargo` = socio
- `PATCH /api/v1/admin/admin-users/<id>` — editar conta (Dono)
