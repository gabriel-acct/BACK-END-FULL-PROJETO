-- Catálogo de países para o campo de preferência/região no painel (Configuração).
-- Execute no MySQL/MariaDB, depois usuarios_proxy_pais_id.sql e painel_paises_default_brasil_update.sql.
-- Novas contas criadas pelo painel recebem Brasil por padrão (código em create_usuario_proxy).

CREATE TABLE IF NOT EXISTS painel_paises (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(128) NOT NULL,
  codigo_iso2 CHAR(2) NULL DEFAULT NULL COMMENT 'ISO 3166-1 alpha-2 quando aplicável',
  ordem INT NOT NULL DEFAULT 0,
  ativo TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uq_painel_paises_nome (nome),
  UNIQUE KEY uq_painel_paises_iso2 (codigo_iso2),
  KEY idx_painel_paises_ativo_ordem (ativo, ordem)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_paises (nome, codigo_iso2, ordem) VALUES
  ('Brasil', 'BR', 0),
  ('Argentina', 'AR', 10),
  ('Bolívia', 'BO', 15),
  ('Chile', 'CL', 20),
  ('Colômbia', 'CO', 25),
  ('Equador', 'EC', 30),
  ('Paraguai', 'PY', 35),
  ('Peru', 'PE', 40),
  ('Uruguai', 'UY', 45),
  ('Venezuela', 'VE', 50),
  ('México', 'MX', 55),
  ('Estados Unidos', 'US', 60),
  ('Canadá', 'CA', 65),
  ('Portugal', 'PT', 70),
  ('Angola', 'AO', 75),
  ('Moçambique', 'MZ', 80),
  ('França', 'FR', 85),
  ('Espanha', 'ES', 90),
  ('Reino Unido', 'GB', 95),
  ('Alemanha', 'DE', 100),
  ('Itália', 'IT', 105),
  ('China', 'CN', 110),
  ('Índia', 'IN', 115),
  ('Japão', 'JP', 120),
  ('Outro — não listado', NULL, 900);
