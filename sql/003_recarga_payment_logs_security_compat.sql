-- Versão compatível com MySQL 5.7 / MariaDB (sem IF NOT EXISTS em colunas)

ALTER TABLE painel_recarga_payment_logs
  MODIFY pedido_id BIGINT UNSIGNED NULL;

-- Execute cada linha; ignore erro "Duplicate column" se já existir
ALTER TABLE painel_recarga_payment_logs ADD COLUMN client_ip VARCHAR(45) NULL AFTER id_externo;
ALTER TABLE painel_recarga_payment_logs ADD COLUMN user_agent VARCHAR(255) NULL AFTER client_ip;
ALTER TABLE painel_recarga_payment_logs ADD COLUMN request_id VARCHAR(64) NULL AFTER user_agent;
ALTER TABLE painel_recarga_payment_logs ADD COLUMN severity VARCHAR(16) NOT NULL DEFAULT 'info' AFTER request_id;

ALTER TABLE painel_recarga_payment_logs ADD KEY idx_prpl_event_created (event_type, created_at);
ALTER TABLE painel_recarga_payment_logs ADD KEY idx_prpl_pedido (pedido_id);
ALTER TABLE painel_recarga_payment_logs ADD KEY idx_prpl_severity (severity, created_at);
