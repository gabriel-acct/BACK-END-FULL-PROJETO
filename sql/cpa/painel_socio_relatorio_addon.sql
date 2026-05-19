-- Adiciona permissão «socio.relatorio» ao cargo sócio em bases já migradas antes desta permissão existir.

INSERT IGNORE INTO painel_permissions (code, descricao) VALUES
  ('socio.relatorio', 'Acessar relatório e auditoria do sócio');

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, 'socio.relatorio'
FROM painel_cargos c
WHERE c.slug = 'socio';
