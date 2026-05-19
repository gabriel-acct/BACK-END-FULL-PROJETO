-- Logs de pagamento: IP, user-agent, severidade e pedido_id alinhado ao BIGINT dos pedidos

ALTER TABLE painel_recarga_payment_logs
  MODIFY pedido_id BIGINT UNSIGNED NULL;

ALTER TABLE painel_recarga_payment_logs
  ADD COLUMN IF NOT EXISTS client_ip VARCHAR(45) NULL AFTER id_externo,
  ADD COLUMN IF NOT EXISTS user_agent VARCHAR(255) NULL AFTER client_ip,
  ADD COLUMN IF NOT EXISTS request_id VARCHAR(64) NULL AFTER user_agent,
  ADD COLUMN IF NOT EXISTS severity VARCHAR(16) NOT NULL DEFAULT 'info' AFTER request_id;

-- MySQL < 8.0.12 não tem IF NOT EXISTS em ADD COLUMN — use manualmente se falhar:
-- ALTER TABLE painel_recarga_payment_logs ADD COLUMN client_ip VARCHAR(45) NULL AFTER id_externo;
-- ALTER TABLE painel_recarga_payment_logs ADD COLUMN user_agent VARCHAR(255) NULL AFTER client_ip;
-- ALTER TABLE painel_recarga_payment_logs ADD COLUMN request_id VARCHAR(64) NULL AFTER user_agent;
-- ALTER TABLE painel_recarga_payment_logs ADD COLUMN severity VARCHAR(16) NOT NULL DEFAULT 'info' AFTER request_id;

ALTER TABLE painel_recarga_payment_logs
  ADD KEY IF NOT EXISTS idx_prpl_event_created (event_type, created_at),
  ADD KEY IF NOT EXISTS idx_prpl_pedido (pedido_id),
  ADD KEY IF NOT EXISTS idx_prpl_severity (severity, created_at);
