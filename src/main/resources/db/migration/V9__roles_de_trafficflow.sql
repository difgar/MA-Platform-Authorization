-- Tres roles para TrafficFlow (difgar, 2026-10-04):
--
--   trafficflow_admin  : todo ('*:*'). Es el 'admin' de V6 RENOMBRADO, no una fila nueva:
--                        auth_user_role apunta al id, asi que quien ya era administrador lo
--                        sigue siendo sin tocar su usuario.
--   trafficflow_user   : crea y edita redes, servicios, campanas, enlaces, reglas y endpoints,
--                        y lo lee todo; NO reenvia ni barre postbacks.
--   trafficflow_viewer : solo lectura ('*:leer').
--
-- trafficflow_user va SIN comodin porque el comodin no admite exclusiones (ver V6): es el
-- catalogo menos reenvios:crear y barridos:crear, las dos acciones que hacen salir un
-- postback hacia la red, y el pago es nuestro. Precio: un permiso nuevo del catalogo NO le
-- llega solo; hay que concederlo en la migracion que lo cree.
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea. La base de
-- produccion se rehizo a mano el 2026-10-04 con ids aleatorios (apps, roles y permisos) y
-- ya trae los tres roles y sus permisos; una version anterior de esta migracion, con los ids
-- de V5/V6, fallo alli por clave ajena. Asi sirve igual en una base nueva (los tests, local)
-- y en produccion, donde no hace nada. Los ids literales solo se usan para filas que no
-- existan, y SQL portable entre PostgreSQL y MySQL (sin || ni funciones de uuid).

-- 1. admin -> trafficflow_admin (solo si aun se llama admin).
UPDATE auth_role
   SET name = 'trafficflow_admin', updated_at = TIMESTAMP '2026-10-04 00:00:00'
 WHERE name = 'admin'
   AND app_id = (SELECT id FROM auth_app WHERE name = 'trafficflow')
   AND NOT EXISTS (SELECT 1 FROM (SELECT r.id FROM auth_role r JOIN auth_app a ON a.id = r.app_id
                                   WHERE a.name = 'trafficflow' AND r.name = 'trafficflow_admin') t);

-- 2. El permiso comodin de lectura de trafficflow.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT 'b0000000-0000-4000-8000-0000000000f7', a.id, '*', 'leer', 'Leer todo en trafficflow', TIMESTAMP '2026-10-04 00:00:00'
  FROM auth_app a
 WHERE a.name = 'trafficflow'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p WHERE p.app_id = a.id AND p.resource = '*' AND p.verb = 'leer');

-- 3. Los roles que falten.
INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-000000000007', 'trafficflow_user', a.id,
       'Configura TrafficFlow (redes, servicios, campanas, enlaces, reglas, endpoints) y lo ve todo, pero no reenvia ni barre postbacks. Sin comodin: cada permiso nuevo del catalogo hay que concederselo a mano.',
       TIMESTAMP '2026-10-04 00:00:00', TIMESTAMP '2026-10-04 00:00:00'
  FROM auth_app a
 WHERE a.name = 'trafficflow'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'trafficflow_user');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-000000000008', 'trafficflow_viewer', a.id,
       'Solo lectura de TrafficFlow.',
       TIMESTAMP '2026-10-04 00:00:00', TIMESTAMP '2026-10-04 00:00:00'
  FROM auth_app a
 WHERE a.name = 'trafficflow'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'trafficflow_viewer');

-- 4. Los permisos de cada rol que falten.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'trafficflow'
   AND (   (r.name = 'trafficflow_admin'  AND p.resource = '*' AND p.verb = '*')
        OR (r.name = 'trafficflow_viewer' AND p.resource = '*' AND p.verb = 'leer')
        OR (r.name = 'trafficflow_user'   AND p.resource <> '*'
            AND (p.resource, p.verb) NOT IN (('reenvios', 'crear'), ('barridos', 'crear'))))
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
