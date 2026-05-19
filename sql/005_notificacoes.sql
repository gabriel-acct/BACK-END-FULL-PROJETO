-- Notificações admin → usuários do painel (sub-usuários)

CREATE TABLE IF NOT EXISTS painel_notificacoes (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  titulo VARCHAR(200) NOT NULL,
  mensagem TEXT NOT NULL,
  tipo ENUM('normal', 'critico') NOT NULL DEFAULT 'normal',
  alvo_tipo ENUM('todos', 'usuarios') NOT NULL DEFAULT 'todos',
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  criado_por VARCHAR(64) NOT NULL,
  criado_em DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  atualizado_em DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  expira_em DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY idx_notif_ativo_criado (ativo, criado_em DESC),
  KEY idx_notif_tipo (tipo, ativo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS painel_notificacoes_alvos (
  notificacao_id BIGINT UNSIGNED NOT NULL,
  subuser_id VARCHAR(64) NOT NULL COMMENT 'ID do sub-usuário na API (JWT sub)',
  PRIMARY KEY (notificacao_id, subuser_id),
  KEY idx_notif_alvos_user (subuser_id),
  CONSTRAINT fk_notif_alvos_notif FOREIGN KEY (notificacao_id) REFERENCES painel_notificacoes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS painel_notificacoes_estado (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  notificacao_id BIGINT UNSIGNED NOT NULL,
  subuser_id VARCHAR(64) NOT NULL,
  lida TINYINT(1) NOT NULL DEFAULT 0,
  critico_ack TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = usuário fechou o aviso crítico no painel',
  oculto TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = usuário removeu da própria lista',
  atualizado_em DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_notif_estado (notificacao_id, subuser_id),
  KEY idx_notif_estado_user (subuser_id, lida),
  CONSTRAINT fk_notif_estado_notif FOREIGN KEY (notificacao_id) REFERENCES painel_notificacoes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_permissions (code, descricao, grupo) VALUES
  ('notifications.view', 'Ver notificações enviadas', 'notifications'),
  ('notifications.manage', 'Criar e gerenciar notificações', 'notifications');

-- Evita UNION com literais (erro 1271: mix of collations em alguns servidores MySQL)
INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN painel_permissions p
WHERE c.slug IN ('dono', 'administrador')
  AND p.code IN ('notifications.view', 'notifications.manage');
