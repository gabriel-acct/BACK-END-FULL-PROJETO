-- Logo por URL (link) — execute após 007_site_branding.sql

ALTER TABLE painel_site_branding
  ADD COLUMN logo_url VARCHAR(512) NULL COMMENT 'URL pública da imagem do logo' AFTER support_whatsapp;
