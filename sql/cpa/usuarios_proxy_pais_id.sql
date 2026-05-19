-- Referência opcional ao país preferido pelo usuário na tabela usuarios_proxy.

ALTER TABLE usuarios_proxy
  ADD COLUMN pais_id INT UNSIGNED NULL DEFAULT NULL AFTER cargo_id,
  ADD KEY idx_usuarios_proxy_pais (pais_id);

ALTER TABLE usuarios_proxy
  ADD CONSTRAINT fk_usuarios_proxy_pais
  FOREIGN KEY (pais_id) REFERENCES painel_paises(id)
  ON DELETE SET NULL;

-- Opcional: preencher todas as linhas sem país com Brasil — ver painel_paises_default_brasil_update.sql
