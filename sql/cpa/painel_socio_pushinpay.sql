-- Conta PushinPay por sócio (recebimento PIX dos clientes criados por ele e do próprio sócio).

CREATE TABLE IF NOT EXISTS painel_socio_pushinpay (
  socio_username VARCHAR(128) NOT NULL,
  api_base VARCHAR(256) NULL COMMENT 'Null = mesma base da config global / env',
  api_token TEXT NOT NULL COMMENT 'Bearer da conta PushinPay do sócio',
  webhook_secret VARCHAR(512) NULL COMMENT 'Mesmo valor configurado no painel PushinPay (header)',
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
