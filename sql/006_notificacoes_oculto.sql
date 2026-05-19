-- Ocultar notificação só para o usuário (cliente remove da própria lista)
-- MySQL < 8.0.12: use 006_notificacoes_oculto_compat.sql ou rode manualmente se a coluna já existir.

ALTER TABLE painel_notificacoes_estado
  ADD COLUMN oculto TINYINT(1) NOT NULL DEFAULT 0
    COMMENT '1 = usuário removeu da própria lista'
  AFTER critico_ack;
