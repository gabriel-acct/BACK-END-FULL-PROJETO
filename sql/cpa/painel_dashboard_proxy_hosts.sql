-- Hosts sugeridos no painel do cliente (Visão geral / dashboard).
-- Quem edita: ARE CEO (cargo com bypass_all) via API PUT /api/admin/dono/dashboard-proxy-hosts
-- Quem lê: qualquer usuário logado em GET /api/me (campo dashboard_proxy_hosts).

CREATE TABLE IF NOT EXISTS painel_dashboard_proxy_hosts (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  hostname VARCHAR(253) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  atualizado_em TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_painel_dashboard_proxy_hosts_hostname (hostname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Valores iniciais (ajuste ou apague após rodar o CREATE).
-- Se o hostname já existir, só atualiza ordem e ativo.
INSERT INTO painel_dashboard_proxy_hosts (hostname, sort_order, ativo) VALUES
  ('cpa-proxy.shop', 0, 1),
  ('proxy.cpaproxys.shop', 1, 1),
  ('www.cpaproxys.shop', 2, 1),
  ('74.81.81.81', 3, 1),
  ('148.251.5.30', 4, 1),
  ('67.213.114.47', 5, 1),
  ('67.213.114.45', 6, 1)
ON DUPLICATE KEY UPDATE
  sort_order = VALUES(sort_order),
  ativo = VALUES(ativo);
