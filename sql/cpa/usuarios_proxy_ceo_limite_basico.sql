-- ARE CEO: baseline de limite_gb ao marcar «custo pago».
-- Enquanto custo_pago=1 a conta não entra nos totais; após recarga (custo_pago=0) o valor ref. conta só max(0, limite_gb − baseline).
ALTER TABLE usuarios_proxy
  ADD COLUMN ceo_limite_gb_basico DECIMAL(24, 8) NULL DEFAULT NULL
  COMMENT 'limite_gb na última marcação custo_pago; ARE CEO valoriza apenas o acréscimo';
