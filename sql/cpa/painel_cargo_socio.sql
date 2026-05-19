-- Cargo «sócio»: painel próprio para criar usuários limitados pelo pool de GB do próprio sócio.

INSERT IGNORE INTO painel_permissions (code, descricao) VALUES
  ('socio.panel', 'Acessar área «Meus clientes» (sócio)'),
  ('socio.relatorio', 'Acessar relatório e auditoria do sócio'),
  ('socio.users.create', 'Criar usuários sob o pool do sócio'),
  ('socio.users.view', 'Ver lista de usuários criados pelo sócio'),
  ('socio.users.quota', 'Alterar limite_gb dos usuários criados pelo sócio'),
  ('socio.users.logs', 'Ver histórico de acessos dos usuários criados pelo sócio');

INSERT IGNORE INTO painel_cargos (slug, nome, bypass_all)
VALUES ('socio', 'Sócio', 0);

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN (
  SELECT 'socio.panel' AS code
  UNION ALL SELECT 'socio.relatorio'
  UNION ALL SELECT 'socio.users.create'
  UNION ALL SELECT 'socio.users.view'
  UNION ALL SELECT 'socio.users.quota'
  UNION ALL SELECT 'socio.users.logs'
) p
WHERE c.slug = 'socio';
