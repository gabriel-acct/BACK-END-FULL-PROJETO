-- Configurações de recarga/PushinPay somente no MySQL (execute após 002 e 003)
-- Ignore erros "Duplicate column" se já tiver rodado.

ALTER TABLE painel_pushinpay_config
  ADD COLUMN webhook_force_secret TINYINT(1) NOT NULL DEFAULT 1 AFTER webhook_require_secret;

ALTER TABLE painel_pushinpay_config
  ADD COLUMN recarga_pix_sync_max_per_hour INT UNSIGNED NOT NULL DEFAULT 60 AFTER recarga_pix_max_per_hour;

ALTER TABLE painel_recarga_config
  ADD COLUMN max_total_reais DECIMAL(12, 2) NOT NULL DEFAULT 50000.00 AFTER gb_step;

UPDATE painel_pushinpay_config SET
  webhook_force_secret = 1,
  recarga_pix_sync_max_per_hour = 60
WHERE id = 1;

UPDATE painel_recarga_config SET max_total_reais = 50000.00 WHERE id = 1 AND (max_total_reais IS NULL OR max_total_reais = 0);
