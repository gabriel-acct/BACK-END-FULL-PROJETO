-- Revendedor: identidade visual para clientes + permissão de marca.

CREATE TABLE IF NOT EXISTS painel_socio_branding (
  admin_username VARCHAR(64) NOT NULL,
  site_name VARCHAR(120) NULL,
  site_tagline VARCHAR(255) NULL,
  login_title VARCHAR(160) NULL,
  login_subtitle VARCHAR(512) NULL,
  footer_text VARCHAR(512) NULL,
  support_email VARCHAR(190) NULL,
  support_whatsapp VARCHAR(40) NULL,
  logo_url VARCHAR(512) NULL,
  logo_filename VARCHAR(120) NULL,
  favicon_filename VARCHAR(120) NULL,
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  updated_by VARCHAR(64) NULL,
  PRIMARY KEY (admin_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_cargo_permissoes (cargo_id, permission_code)
SELECT c.id, 'socio.branding.manage'
FROM painel_cargos c
WHERE c.slug = 'socio';
