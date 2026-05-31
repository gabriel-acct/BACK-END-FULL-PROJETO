-- =============================================================================
-- CPA Proxy — instalação completa do módulo «Sócio» (revenda com pool de GB)
-- Banco: CPA_DB_NAME (ex.: proxys_rotativas)
--
-- Ordem recomendada (este arquivo já segue essa ordem):
--   1) Coluna criado_por em usuarios_proxy
--   2) Cargo + permissões socio.*
--   3) Tabelas painel_socio_* e colunas PIX em pedidos
--
-- Se algum ALTER falhar com «Duplicate column», a coluna já existe — pode ignorar.
-- =============================================================================

-- --- 1) Vínculo sócio → clientes ------------------------------------------------
ALTER TABLE usuarios_proxy
  ADD COLUMN criado_por VARCHAR(128) NULL COMMENT 'Username do sócio que criou a conta';

ALTER TABLE usuarios_proxy
  ADD KEY idx_usuarios_proxy_criado_por (criado_por);

-- --- 2) Cargo «sócio» e permissões ------------------------------------------------
INSERT IGNORE INTO painel_permissions (code, descricao) VALUES
  ('socio.panel', 'Acessar área «Meus clientes» (sócio)'),
  ('socio.relatorio', 'Acessar relatório e auditoria do sócio'),
  ('socio.users.create', 'Criar usuários sob o pool do sócio'),
  ('socio.users.view', 'Ver lista de usuários criados pelo sócio'),
  ('socio.users.quota', 'Alterar limite_gb dos usuários criados pelo sócio'),
  ('socio.users.logs', 'Ver histórico de acessos dos usuários criados pelo sócio');

INSERT IGNORE INTO painel_cargos (slug, nome, bypass_all)
VALUES ('socio', 'Sócio', 0);

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN (
  SELECT 'socio.panel' AS code
  UNION ALL SELECT 'socio.relatorio'
  UNION ALL SELECT 'socio.users.create'
  UNION ALL SELECT 'socio.users.view'
  UNION ALL SELECT 'socio.users.quota'
  UNION ALL SELECT 'socio.users.logs'
) p
WHERE c.slug = 'socio';

-- --- 3) PushinPay por sócio -------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_socio_pushinpay (
  socio_username VARCHAR(128) NOT NULL,
  api_base VARCHAR(256) NULL COMMENT 'Null = mesma base da config global / env',
  api_token TEXT NOT NULL COMMENT 'Bearer da conta PushinPay do sócio',
  webhook_secret VARCHAR(512) NULL COMMENT 'Mesmo valor configurado no painel PushinPay (header)',
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- 4) Marca do menu (sócio + clientes criado_por) -------------------------------
CREATE TABLE IF NOT EXISTS painel_socio_panel_branding (
  socio_username VARCHAR(128) NOT NULL,
  titulo_sidebar VARCHAR(64) NULL COMMENT 'Nome ao lado da logo (substitui CPAPROXY)',
  subtitulo_sidebar VARCHAR(96) NULL COMMENT 'Linha pequena abaixo do título',
  logo_url VARCHAR(768) NULL COMMENT 'HTTPS — URL direta para imagem (PNG/JPG/WebP recomendados)',
  atualizado_em TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- 5) Hosts de proxy personalizados (aprovação do dono) ------------------------
CREATE TABLE IF NOT EXISTS painel_socio_proxy_hosts (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  socio_username VARCHAR(191) NOT NULL,
  hostname VARCHAR(253) NOT NULL,
  status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  reviewed_at TIMESTAMP NULL DEFAULT NULL,
  reviewed_by VARCHAR(191) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_socio_hostname (socio_username, hostname),
  KEY idx_status_created (status, created_at),
  KEY idx_socio (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --- 6) PIX: origem global vs conta do sócio --------------------------------------
ALTER TABLE painel_recarga_pedidos_pix
  ADD COLUMN pushinpay_source VARCHAR(16) NOT NULL DEFAULT 'global'
    COMMENT 'global | socio' AFTER payload_pix,
  ADD COLUMN socio_billing_username VARCHAR(128) NULL
    COMMENT 'Username do sócio cujo token gerou a cobrança' AFTER pushinpay_source;
