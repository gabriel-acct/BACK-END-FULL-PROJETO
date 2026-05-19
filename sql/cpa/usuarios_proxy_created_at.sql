-- Data de criação da conta proxy no painel.
--
-- Produção atual costuma usar o nome **`criado_em`**. Este script adiciona **`created_at`**.
-- Se já existir `created_at`, prefira só renomear: veja usuarios_proxy_criado_em.sql
--
-- O código do back-end tenta primeiro `criado_em`, depois `created_at`.

ALTER TABLE usuarios_proxy
  ADD COLUMN created_at DATETIME NULL DEFAULT NULL AFTER cargo_id;

CREATE INDEX idx_usuarios_proxy_created_at ON usuarios_proxy (created_at);
