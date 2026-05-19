-- Preenche contas sem país com Brasil (após painel_paises.sql e usuarios_proxy_pais_id.sql).
UPDATE usuarios_proxy u
INNER JOIN painel_paises p ON p.codigo_iso2 = 'BR' AND p.ativo = 1
SET u.pais_id = p.id
WHERE u.pais_id IS NULL;
