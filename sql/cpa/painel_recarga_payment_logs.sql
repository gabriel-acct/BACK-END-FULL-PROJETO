-- Logs de eventos de pagamento/recarga PIX (admin: separado de proxy_access_logs).
-- Execute no mesmo banco do painel.

CREATE TABLE IF NOT EXISTS painel_recarga_payment_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type VARCHAR(80) NOT NULL,
  source VARCHAR(32) NOT NULL COMMENT 'api | webhook | system',
  username VARCHAR(128) NULL,
  pedido_id INT NULL,
  id_externo VARCHAR(80) NULL,
  meta MEDIUMTEXT NULL COMMENT 'JSON serializado (resumo do evento)',
  PRIMARY KEY (id),
  KEY idx_prpl_created (created_at),
  KEY idx_prpl_user (username(64)),
  KEY idx_prpl_ext (id_externo(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissão opcional: quem tiver só logs.payments vê estes logs sem logs.full de proxy.
INSERT IGNORE INTO painel_permissions (code, descricao)
VALUES ('logs.payments', 'Ver logs de pagamento PIX / recarga (sem tráfego de proxy)');
