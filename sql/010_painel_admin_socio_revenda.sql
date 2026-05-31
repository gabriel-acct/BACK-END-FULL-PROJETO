-- Proxy Private (painel_reseller): revendedor cria sub-usuários limitado ao pool de GB.

ALTER TABLE painel_admin_users
  ADD COLUMN limite_gb DECIMAL(12, 3) NULL
    COMMENT 'Pool de GB para revenda (cargo socio); soma dos limite_gb dos sub-usuários criados';

INSERT IGNORE INTO painel_cargos (slug, nome, bypass_all)
VALUES ('socio', 'Sócio / Revendedor', 0);

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, p.code
FROM painel_cargos c
CROSS JOIN (
  SELECT 'dashboard.view' AS code
  UNION ALL SELECT 'users.view'
  UNION ALL SELECT 'users.create'
) p
WHERE c.slug = 'socio';
