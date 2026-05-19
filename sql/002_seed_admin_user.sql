-- Cria usuário admin inicial (cargo Dono).
-- Senha padrão de desenvolvimento: Admin@2026
-- Troque após o primeiro login em produção.
--
-- Hash werkzeug pbkdf2:sha256 para "Admin@2026" (validar com check_password_hash no back-end).

INSERT INTO painel_admin_users (username, password_hash, nome, email, cargo_id, ativo)
SELECT
  'admin',
  'pbkdf2:sha256:1000000$rMTMZgfceSMwwCMa$0b821f38978508868be9c736ab586803279d79d12e74028c29bcd4fbd4e23ff2',
  'Administrador Principal',
  NULL,
  c.id,
  1
FROM painel_cargos c
WHERE c.slug = 'dono'
  AND NOT EXISTS (SELECT 1 FROM painel_admin_users WHERE username = 'admin');

INSERT INTO painel_audit_log (actor_username, action, target_type, target_key, detail)
VALUES ('system', 'admin.seed', 'admin_user', 'admin', 'Usuário admin inicial criado via migração SQL');
