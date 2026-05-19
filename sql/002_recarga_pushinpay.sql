-- Recarga PIX via PushinPay — execute no banco painel_reseller

CREATE TABLE IF NOT EXISTS painel_recarga_config (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  preco_por_gb_reais DECIMAL(10, 2) NOT NULL DEFAULT 9.90,
  gb_min DECIMAL(12, 4) NOT NULL DEFAULT 1.0,
  gb_max DECIMAL(12, 4) NOT NULL DEFAULT 500.0,
  gb_step DECIMAL(12, 4) NOT NULL DEFAULT 1.0,
  max_total_reais DECIMAL(12, 2) NOT NULL DEFAULT 50000.00,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_recarga_config (id) VALUES (1);

CREATE TABLE IF NOT EXISTS painel_recarga_descontos (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  nome VARCHAR(160) NOT NULL DEFAULT '',
  gb_minimo DECIMAL(12, 4) NOT NULL,
  percentual_desconto DECIMAL(6, 2) NULL,
  valor_fixo_reais DECIMAL(10, 2) NULL,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  ordem INT NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_recarga_desc_ativo (ativo, gb_minimo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS painel_pushinpay_config (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  api_base VARCHAR(256) NULL,
  api_token TEXT NULL,
  site_public_url VARCHAR(512) NULL,
  webhook_secret VARCHAR(512) NULL,
  webhook_header VARCHAR(128) NULL,
  webhook_require_secret TINYINT(1) NOT NULL DEFAULT 1,
  webhook_force_secret TINYINT(1) NOT NULL DEFAULT 1,
  recarga_pix_max_per_hour INT UNSIGNED NOT NULL DEFAULT 30,
  recarga_pix_sync_max_per_hour INT UNSIGNED NOT NULL DEFAULT 60,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_pushinpay_config (id) VALUES (1);

CREATE TABLE IF NOT EXISTS painel_recarga_pedidos_pix (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(128) NOT NULL COMMENT 'external_subuser_id (DataImpulse)',
  preco_id BIGINT NULL,
  gb_credito DECIMAL(18, 6) NOT NULL,
  valor_reais DECIMAL(18, 2) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  id_externo VARCHAR(80) NOT NULL,
  payload_pix MEDIUMTEXT NOT NULL,
  pushinpay_source VARCHAR(16) NOT NULL DEFAULT 'global',
  socio_billing_username VARCHAR(128) NULL,
  criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_pushin_id (id_externo),
  KEY idx_user_criado (username, criado_em DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS painel_recarga_payment_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type VARCHAR(80) NOT NULL,
  source VARCHAR(32) NOT NULL,
  username VARCHAR(128) NULL,
  pedido_id BIGINT UNSIGNED NULL,
  id_externo VARCHAR(80) NULL,
  meta MEDIUMTEXT NULL,
  PRIMARY KEY (id),
  KEY idx_prpl_created (created_at),
  KEY idx_prpl_user (username(64)),
  KEY idx_prpl_ext (id_externo(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
