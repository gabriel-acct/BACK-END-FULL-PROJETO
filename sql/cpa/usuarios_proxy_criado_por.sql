-- Vínculo de contas criadas por um sócio (revendedor). `limite_gb` do sócio = teto de GB
-- que pode ser distribuído entre os filhos (soma dos limite_gb onde criado_por = username do sócio).
-- Os filhos usam a mesma porta (gateway HTTP 823 ou SOCKS5 824) que o próprio sócio.
-- Se a coluna já existir, ignore o erro do primeiro ALTER.

ALTER TABLE usuarios_proxy
  ADD COLUMN criado_por VARCHAR(128) NULL COMMENT 'Username do sócio que criou a conta';

ALTER TABLE usuarios_proxy
  ADD KEY idx_usuarios_proxy_criado_por (criado_por);
