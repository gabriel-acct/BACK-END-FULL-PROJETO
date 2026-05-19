-- Ocultar notificação só para o usuário (cliente remove da própria lista)

ALTER TABLE painel_notificacoes_estado
  ADD COLUMN IF NOT EXISTS oculto TINYINT(1) NOT NULL DEFAULT 0
    COMMENT '1 = usuário removeu da própria lista'
  AFTER critico_ack;
