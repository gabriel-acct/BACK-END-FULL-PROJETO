-- Domínios de destino bloqueados no proxy (lista gerida no painel admin).
-- O gateway/proxy pode consultar GET /api/blocked-hosts (público) para aplicar o bloqueio.

CREATE TABLE IF NOT EXISTS painel_hosts_bloqueados (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  dominio VARCHAR(253) NOT NULL,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  nota VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_painel_hosts_dominio (dominio),
  KEY idx_painel_hosts_ativo (ativo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissão para administradores gerenciarem a lista (conceda ao cargo desejado).
INSERT IGNORE INTO painel_permissions (code, descricao)
VALUES ('hosts.block', 'Gerenciar domínios bloqueados de destino no proxy');

-- Exemplo: dar hosts.block ao cargo «administrador» (ajuste o slug se for outro no seu banco).
INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, 'hosts.block'
FROM painel_cargos c
WHERE c.slug = 'administrador'
LIMIT 1;
