-- Configuração global PushinPay (PIX) no banco. Uma linha (id=1).
-- Valores vazios/null em token/URL fazem fallback para variáveis de ambiente no app.

CREATE TABLE IF NOT EXISTS painel_pushinpay_config (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  api_base VARCHAR(256) NULL COMMENT 'Ex.: https://api.pushinpay.com.br/api',
  api_token TEXT NULL COMMENT 'Bearer da conta principal',
  site_public_url VARCHAR(512) NULL COMMENT 'URL pública do back-end (webhook)',
  webhook_secret VARCHAR(512) NULL COMMENT 'Header enviado pela PushinPay no webhook global',
  webhook_header VARCHAR(128) NULL COMMENT 'Nome do header (ex.: X-Webhook-Token)',
  webhook_require_secret TINYINT(1) NOT NULL DEFAULT 1,
  recarga_pix_max_per_hour INT UNSIGNED NOT NULL DEFAULT 30,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_pushinpay_config (id) VALUES (1);
