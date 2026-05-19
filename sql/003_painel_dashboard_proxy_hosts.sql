-- Hosts exibidos no seletor de credencial do painel do cliente
CREATE TABLE IF NOT EXISTS painel_dashboard_proxy_hosts (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  hostname VARCHAR(253) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  atualizado_em TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_painel_dashboard_proxy_hosts_hostname (hostname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO painel_dashboard_proxy_hosts (hostname, sort_order, ativo)
SELECT 'proxy.cpaproxys.shop', 10, 1
WHERE NOT EXISTS (
  SELECT 1 FROM painel_dashboard_proxy_hosts WHERE hostname = 'proxy.cpaproxys.shop'
);

INSERT INTO painel_dashboard_proxy_hosts (hostname, sort_order, ativo)
SELECT 'cpaproxys.shop', 20, 1
WHERE NOT EXISTS (
  SELECT 1 FROM painel_dashboard_proxy_hosts WHERE hostname = 'cpaproxys.shop'
);
