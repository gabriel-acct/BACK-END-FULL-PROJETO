-- Preferência de threads por conta (painel do cliente → Configurações).
-- Valor padrão sugerido: 1800. Ajuste no app conforme o consumidor (ex.: cliente de proxy) ler este campo.

CREATE TABLE IF NOT EXISTS painel_usuario_threads (
  username VARCHAR(128) NOT NULL,
  threads INT UNSIGNED NOT NULL DEFAULT 1800,
  atualizado_em TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Opcional: FK para usuarios_proxy(username) se o tipo/collation bater no seu banco.
