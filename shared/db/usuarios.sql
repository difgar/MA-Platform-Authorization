-- Los dos primeros administradores (difgar, 2026-10-03). Sustituye los marcadores de V2
-- (usuario1@pendiente.local, usuario2@pendiente.local): el README del auth deja este paso
-- como manual, y para crear usuarios desde el admin primero hay que poder entrar.
--
-- Cada uno: admin de la app `admin` (c0..01) y admin de `trafficflow` (c0..06, permiso *:*).
-- Los roles de fgf de los marcadores se quitan a proposito (fgf fuera de alcance).
-- Idempotente. Se ejecuta como ma_auth sobre la base ma_auth:
--   PGPASSWORD=... psql "host=127.0.0.1 port=15441 dbname=ma_auth user=ma_auth" -f usuarios.sql
BEGIN;
UPDATE auth_user SET email = 'it@mobile-americas.com', active = TRUE, updated_at = now()
 WHERE id = 'd0000000-0000-4000-8000-000000000001';
UPDATE auth_user SET email = 'difgar@gmail.com',       active = TRUE, updated_at = now()
 WHERE id = 'd0000000-0000-4000-8000-000000000002';
DELETE FROM auth_user_role
 WHERE user_id IN ('d0000000-0000-4000-8000-000000000001', 'd0000000-0000-4000-8000-000000000002');
INSERT INTO auth_user_role (user_id, role_id) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000006'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000006');
COMMIT;

SELECT u.email, a.name AS app, r.name AS rol
  FROM auth_user u
  JOIN auth_user_role ur ON ur.user_id = u.id
  JOIN auth_role r ON r.id = ur.role_id
  JOIN auth_app a ON a.id = r.app_id
 ORDER BY u.email, a.name;
