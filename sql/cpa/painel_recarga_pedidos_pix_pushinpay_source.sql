-- Origem da cobrança PIX (conta global vs conta PushinPay do sócio).

ALTER TABLE painel_recarga_pedidos_pix
  ADD COLUMN pushinpay_source VARCHAR(16) NOT NULL DEFAULT 'global'
    COMMENT 'global | socio' AFTER payload_pix,
  ADD COLUMN socio_billing_username VARCHAR(128) NULL
    COMMENT 'Username do sócio cujo token gerou a cobrança' AFTER pushinpay_source;
