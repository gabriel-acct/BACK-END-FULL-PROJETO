-- Marca visual do menu para sócio e seus clientes (`criado_por`); sócio edita nas Configurações.

CREATE TABLE IF NOT EXISTS painel_socio_panel_branding (
  socio_username VARCHAR(128) NOT NULL,
  titulo_sidebar VARCHAR(64) NULL COMMENT 'Nome ao lado da logo (substitui CPAPROXY)',
  subtitulo_sidebar VARCHAR(96) NULL COMMENT 'Linha pequena abaixo do título',
  logo_url VARCHAR(768) NULL COMMENT 'HTTPS — URL direta para imagem (PNG/JPG/WebP recomendados)',
  atualizado_em TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (socio_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
