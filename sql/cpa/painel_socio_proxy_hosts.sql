-- Hosts de proxy sugeridos por sócio (pendente → dono aprova/rejeita).
-- Quando existir ao menos um host aprovado para o sócio, /api/me devolve só esses hosts
-- para o sócio e contas com criado_por = esse sócio (sem misturar com a lista global).

CREATE TABLE IF NOT EXISTS painel_socio_proxy_hosts (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  socio_username VARCHAR(191) NOT NULL,
  hostname VARCHAR(253) NOT NULL,
  status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  reviewed_at TIMESTAMP NULL DEFAULT NULL,
  reviewed_by VARCHAR(191) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_socio_hostname (socio_username, hostname),
  KEY idx_status_created (status, created_at),
  KEY idx_socio (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
