-- Identidade visual do painel (somente Dono edita via API admin)
-- Execute no banco painel_reseller após os scripts anteriores.

CREATE TABLE IF NOT EXISTS painel_site_branding (
  id TINYINT UNSIGNED NOT NULL DEFAULT 1,
  site_name VARCHAR(120) NOT NULL DEFAULT 'Proxy Private',
  site_tagline VARCHAR(255) NULL,
  login_title VARCHAR(160) NULL,
  login_subtitle VARCHAR(512) NULL,
  footer_text VARCHAR(512) NULL,
  support_email VARCHAR(190) NULL,
  support_whatsapp VARCHAR(40) NULL,
  logo_filename VARCHAR(120) NULL COMMENT 'arquivo em uploads/branding/',
  favicon_filename VARCHAR(120) NULL,
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  updated_by VARCHAR(64) NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO painel_site_branding (id, site_name, site_tagline, login_title, login_subtitle)
VALUES (
  1,
  'Proxy Private',
  'Painel de proxy privado',
  'Entrar na conta',
  'Credencial no formato host:porta:usuario:senha'
)
ON DUPLICATE KEY UPDATE id = id;
