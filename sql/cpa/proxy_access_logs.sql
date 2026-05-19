-- Tabela usada pelo gateway (sistema-proxy-rotativa) e pelo painel (`/api/me/logs`, admin).
-- Execute no mesmo schema MySQL onde está `usuarios_proxy` (ex.: sistema_de_proxys).

CREATE TABLE IF NOT EXISTS proxy_access_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(128) NOT NULL,
    porta INT UNSIGNED NOT NULL,
    dest_host VARCHAR(253) NOT NULL COMMENT 'Hostname principal do destino',
    dest_display VARCHAR(512) NOT NULL COMMENT 'Destino amigável (host:path ou CONNECT host:port)',
    method VARCHAR(16) NOT NULL DEFAULT '',
    bytes_upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_download BIGINT UNSIGNED NOT NULL DEFAULT 0,
    upstream_proxy VARCHAR(160) NULL COMMENT 'Upstream proxy utilizado host:port',
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_user_created (username, created_at DESC),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
