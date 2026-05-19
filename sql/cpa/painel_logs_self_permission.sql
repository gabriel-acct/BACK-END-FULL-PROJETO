-- Histórico de acessos (proxy) da própria conta no painel — `/api/me/logs` e rota «Histórico».
-- Atribui a todos os cargos existentes para que clientes, sócios e demais contas vejam o próprio tráfego.

INSERT IGNORE INTO painel_permissions (code, descricao) VALUES
  ('logs.self', 'Ver histórico de acessos da própria conta (proxy)');

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, 'logs.self'
FROM painel_cargos c;
