-- Valor manual extra (R$) somado ao total ARE CEO na aba «Usuários & custo» (dono apenas).
-- Aplicar migração e reiniciar o back-end. Ajustes via PATCH /api/admin/dono/ceo-valor-extra (+ ceo_pin).

CREATE TABLE IF NOT EXISTS painel_ceo_settings (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
  valor_extra_reais DECIMAL(24, 8) NOT NULL DEFAULT 0,
  atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO painel_ceo_settings (id, valor_extra_reais) VALUES (1, 0);
