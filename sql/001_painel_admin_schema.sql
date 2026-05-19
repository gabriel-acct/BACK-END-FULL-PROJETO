-- Proxy Private — esquema administrativo (MySQL / MariaDB)
-- Execute no banco painel_reseller (ou o DB_NAME do .env).
-- Senha do admin inicial: use o script 002_seed_admin_user.sql após aplicar este arquivo.

-- ---------------------------------------------------------------------------
-- Cargos (RBAC)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_cargos (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  slug VARCHAR(64) NOT NULL,
  nome VARCHAR(120) NOT NULL,
  bypass_all TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = dono, ignora checagem de permissões',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_painel_cargos_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Catálogo de permissões
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_permissions (
  code VARCHAR(80) NOT NULL,
  descricao VARCHAR(255) NOT NULL,
  grupo VARCHAR(40) NOT NULL DEFAULT 'geral' COMMENT 'users | roles | logs | payments | settings',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS painel_cargo_permissoes (
  cargo_id INT UNSIGNED NOT NULL,
  permission_code VARCHAR(80) NOT NULL,
  PRIMARY KEY (cargo_id, permission_code),
  CONSTRAINT fk_pcp_cargo FOREIGN KEY (cargo_id) REFERENCES painel_cargos (id) ON DELETE CASCADE,
  CONSTRAINT fk_pcp_perm FOREIGN KEY (permission_code) REFERENCES painel_permissions (code) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Contas administrativas (separadas dos sub-usuários DataImpulse)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_admin_users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL COMMENT 'bcrypt ou argon2 — nunca texto puro em produção',
  nome VARCHAR(120) NOT NULL,
  email VARCHAR(190) NULL,
  cargo_id INT UNSIGNED NOT NULL,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  ultimo_login_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_painel_admin_username (username),
  KEY idx_painel_admin_cargo (cargo_id),
  CONSTRAINT fk_pau_cargo FOREIGN KEY (cargo_id) REFERENCES painel_cargos (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Auditoria (ações no painel admin)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_audit_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  actor_username VARCHAR(64) NOT NULL,
  action VARCHAR(80) NOT NULL COMMENT 'ex.: user.create, cargo.update, payment.method.create',
  target_type VARCHAR(40) NULL COMMENT 'user | cargo | payment_method | subuser',
  target_key VARCHAR(190) NULL,
  detail TEXT NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  PRIMARY KEY (id),
  KEY idx_audit_created (created_at),
  KEY idx_audit_actor (actor_username),
  KEY idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Formas de pagamento (configuração futura — PIX, cartão, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_payment_methods (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  slug VARCHAR(64) NOT NULL,
  nome VARCHAR(120) NOT NULL,
  tipo VARCHAR(32) NOT NULL COMMENT 'pix | card | manual | other',
  config_json JSON NULL COMMENT 'credenciais / webhook / taxas',
  ativo TINYINT(1) NOT NULL DEFAULT 0,
  ordem INT NOT NULL DEFAULT 0,
  created_by VARCHAR(64) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_payment_methods_slug (slug),
  KEY idx_payment_methods_ativo (ativo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Logs de eventos de pagamento (recargas, webhooks)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_payment_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type VARCHAR(80) NOT NULL,
  source VARCHAR(32) NOT NULL COMMENT 'api | webhook | admin | system',
  username VARCHAR(128) NULL COMMENT 'sub-usuário afetado, se houver',
  payment_method_id INT UNSIGNED NULL,
  external_id VARCHAR(120) NULL,
  amount_cents BIGINT NULL,
  meta JSON NULL,
  PRIMARY KEY (id),
  KEY idx_ppl_created (created_at),
  KEY idx_ppl_user (username(64)),
  KEY idx_ppl_method (payment_method_id),
  CONSTRAINT fk_ppl_method FOREIGN KEY (payment_method_id) REFERENCES painel_payment_methods (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Metadados locais de sub-usuários (vínculo com API externa — futuro)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS painel_subusers_local (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  external_subuser_id VARCHAR(64) NOT NULL COMMENT 'ID na API DataImpulse',
  login VARCHAR(128) NOT NULL,
  label VARCHAR(190) NULL,
  criado_por VARCHAR(64) NULL COMMENT 'admin que criou',
  limite_gb DECIMAL(12, 3) NULL,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_subusers_external (external_subuser_id),
  KEY idx_subusers_login (login),
  KEY idx_subusers_criado_por (criado_por)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Permissões padrão
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO painel_permissions (code, descricao, grupo) VALUES
  ('dashboard.view', 'Ver resumo do painel administrativo', 'settings'),
  ('users.view', 'Listar sub-usuários', 'users'),
  ('users.create', 'Criar sub-usuários', 'users'),
  ('users.update', 'Editar sub-usuários', 'users'),
  ('users.status', 'Ativar / desativar sub-usuários', 'users'),
  ('roles.manage', 'Gerenciar cargos e permissões', 'roles'),
  ('logs.audit', 'Ver logs de auditoria', 'logs'),
  ('logs.payments', 'Ver logs de pagamento', 'logs'),
  ('payments.manage', 'Configurar formas de pagamento', 'payments'),
  ('payments.view', 'Ver formas de pagamento', 'payments');

-- ---------------------------------------------------------------------------
-- Cargos padrão
-- ---------------------------------------------------------------------------
INSERT IGNORE INTO painel_cargos (slug, nome, bypass_all) VALUES
  ('dono', 'Dono', 1),
  ('administrador', 'Administrador', 0),
  ('suporte', 'Suporte', 0);

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN painel_permissions p
WHERE c.slug = 'dono';

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN (
  SELECT 'dashboard.view' AS code
  UNION ALL SELECT 'users.view'
  UNION ALL SELECT 'users.create'
  UNION ALL SELECT 'users.update'
  UNION ALL SELECT 'users.status'
  UNION ALL SELECT 'logs.audit'
  UNION ALL SELECT 'logs.payments'
  UNION ALL SELECT 'payments.view'
  UNION ALL SELECT 'payments.manage'
) p
WHERE c.slug = 'administrador';

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN (
  SELECT 'dashboard.view' AS code
  UNION ALL SELECT 'users.view'
  UNION ALL SELECT 'logs.audit'
) p
WHERE c.slug = 'suporte';
