-- Pedidos de recarga via PIX (PushinPay). Execute no mesmo banco do painel.
-- Ajuste tipos se sua base já tiver esta tabela com definição diferente.

CREATE TABLE IF NOT EXISTS painel_recarga_pedidos_pix (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(128) NOT NULL,
  preco_id BIGINT NULL COMMENT 'NULL = recarga por GB livre; senão FK lógica para painel_recarga_precos',
  gb_credito DECIMAL(18, 6) NOT NULL,
  valor_reais DECIMAL(18, 2) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT 'pending | paid | canceled | expired',
  id_externo VARCHAR(80) NOT NULL COMMENT 'ID retornado pela PushinPay',
  payload_pix MEDIUMTEXT NOT NULL COMMENT 'Copia e cola EMV (pode passar de 64 KiB em alguns casos)',
  criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_pushin_id (id_externo),
  KEY idx_user_criado (username, criado_em DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
