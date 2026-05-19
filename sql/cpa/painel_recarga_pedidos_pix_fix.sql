-- Correções comuns quando o INSERT do pedido PIX falha no MySQL.
-- Rode no MESMO banco do painel (BD_NAME).

-- 1) Código PIX copia-e-cola (EMV) costuma ter centenas de caracteres — VARCHAR(255) estoura.
ALTER TABLE painel_recarga_pedidos_pix
  MODIFY COLUMN payload_pix MEDIUMTEXT NOT NULL COMMENT 'Copia e cola EMV';

-- 2) Recarga "por GB" grava preco_id NULL; se a cola foi criada como NOT NULL sem default, falha.
ALTER TABLE painel_recarga_pedidos_pix
  MODIFY COLUMN preco_id BIGINT NULL COMMENT 'NULL = por GB';

-- 3) UUID PushinPay costuma ter 36 chars; garantir espaço.
ALTER TABLE painel_recarga_pedidos_pix
  MODIFY COLUMN id_externo VARCHAR(80) NOT NULL;
