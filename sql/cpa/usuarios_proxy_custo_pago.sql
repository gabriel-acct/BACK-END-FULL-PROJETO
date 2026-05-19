-- ARE CEO / custo: quando 1, a conta não entra na lista «Usuários & custo» nem nos totais valorizados.
-- Execute no mesmo schema MySQL/MariaDB onde está `usuarios_proxy`.
-- Se a coluna já existir, ignore o erro do ALTER.

ALTER TABLE usuarios_proxy
  ADD COLUMN custo_pago TINYINT(1) NOT NULL DEFAULT 0
  COMMENT '1 = custo/GB tratado como pago (ARE CEO)';
