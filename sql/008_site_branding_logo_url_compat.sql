-- Logo por URL (sem AFTER — MariaDB antigo)

ALTER TABLE painel_site_branding
  ADD COLUMN logo_url VARCHAR(512) NULL COMMENT 'URL pública da imagem do logo';
