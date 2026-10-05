-- El rol 'admin_user' del admin (2026-10-05): la puerta al menu de aplicaciones.
--
-- Por que: quien solo usa TrafficFlow (finanzas@) entraba por admin.mobile-americas.com -el
-- menu desde el que se salta a cada aplicacion- y el authorization server lo rechazaba con
-- error_reason=sin_rol, porque no tenia NINGUN rol en la app admin. 'admin_user' es lo minimo
-- para cruzar esa puerta: apps:leer y nada mas (ni usuarios, ni roles, ni crear o editar
-- apps). Asignarlo sigue siendo a mano, por persona: ninguna migracion da roles a nadie,
-- porque los correos reales no entran en git (ver el final de V6).
--
-- De paso se asegura el 'admin' del admin con '*:*'. En una base nueva lo trae V2; en
-- produccion se creo a mano tras rehacer la base. Aqui solo se completa lo que falte.
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea, igual que V9:
-- la base de produccion se rehizo a mano el 2026-10-04 con ids aleatorios. Los ids
-- literales solo se usan para filas que no existan. SQL portable entre PostgreSQL y MySQL
-- (sin || ni funciones de uuid). MigracionIT reaplica este fichero entero para comprobar
-- que una segunda pasada no cambia nada.

-- 1. Los dos permisos que hacen falta, si faltan (V2 los trae; produccion deberia).
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT 'b0000000-0000-4000-8000-0000000000a1', a.id, 'apps', 'leer', NULL, TIMESTAMP '2026-10-05 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p WHERE p.app_id = a.id AND p.resource = 'apps' AND p.verb = 'leer');

INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT 'b0000000-0000-4000-8000-0000000000a2', a.id, '*', '*', 'Todo en admin', TIMESTAMP '2026-10-05 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p WHERE p.app_id = a.id AND p.resource = '*' AND p.verb = '*');

-- 2. Los roles que falten.
INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-00000000000a', 'admin', a.id, NULL,
       TIMESTAMP '2026-10-05 00:00:00', TIMESTAMP '2026-10-05 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'admin');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-000000000009', 'admin_user', a.id,
       'Puerta al menu de aplicaciones: deja entrar al admin a quien usa otras apps (p. ej. TrafficFlow) para saltar a ellas desde el menu. Solo concede apps:leer.',
       TIMESTAMP '2026-10-05 00:00:00', TIMESTAMP '2026-10-05 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'admin_user');

-- 3. Las concesiones que falten: admin -> '*:*', admin_user -> apps:leer.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'admin'
   AND (   (r.name = 'admin'   AND p.resource = '*'    AND p.verb = '*')
        OR (r.name = 'admin_user' AND p.resource = 'apps' AND p.verb = 'leer'))
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
