-- Hosts/domínios bloqueados globalmente (aplicados aos sub-usuários via API DataImpulse)
CREATE TABLE IF NOT EXISTS painel_blocked_hosts (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  hostname VARCHAR(253) NOT NULL COMMENT 'Domínio bloqueado (ex.: google.com)',
  sort_order INT NOT NULL DEFAULT 0,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  protegido_painel TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Definido pelo painel; cliente não remove',
  criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_painel_blocked_hosts_hostname (hostname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO painel_blocked_hosts (hostname, sort_order, ativo, protegido_painel)
SELECT 'google.com', 10, 1, 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM painel_blocked_hosts WHERE hostname = 'google.com');

INSERT INTO painel_blocked_hosts (hostname, sort_order, ativo, protegido_painel)
SELECT 'youtube.com', 20, 1, 1 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM painel_blocked_hosts WHERE hostname = 'youtube.com');
