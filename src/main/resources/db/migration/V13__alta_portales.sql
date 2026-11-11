-- Alta de la app 'portales' (2026-11-11): el admin de los portales de contenido, con su catalogo
-- de permisos y dos roles (plan: MA-Portal-Docs, admin-portales fases 1-2).
--
-- 26 permisos '<recurso>:<verbo>', los que comprobara MA-Portal-API en el perfil admin:
--   portales c/l/e, contenidos c/l/e/b, categorias c/l/e/b, temas c/l/e/b, destacados l/e,
--   planes c/l/e/b, logros c/l/e/b, uso l            (c=crear l=leer e=editar b=borrar)
-- 'borrar' = ARCHIVAR: ningun codigo del admin borra filas de catalogo; archivar es un cambio de status.
--
-- Dos roles:
--   portales_contenidos     opera el dia a dia: contenidos:* y destacados:editar; el resto, solo leer
--   portales_configuracion  configura: portales, categorias, temas, planes y logros (c/l/e/b o c/l/e);
--                           contenidos, destacados y uso, solo leer
--
-- SIN COMODIN: los roles llevan filas concretas de auth_role_permission. Un '*:*' se expandiria
-- contra el catalogo de la app y daria permisos que aqui se quieren decidir uno a uno. Y el rol
-- 'admin' del admin NO da acceso a esta app: sus roles viven en su propia app (admin), asi que
-- 'portales' solo se entra con uno de estos dos roles.
--
-- Cada persona necesita ademas un rol en la app 'admin' (p. ej. 'admin_user') para ver el menu de
-- aplicaciones. Asignar los roles sigue siendo a mano: shared/db/asignar-rol.sql
-- (-v app=portales -v rol=portales_contenidos).
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea, igual que V9..V12:
-- produccion se rehizo a mano con ids aleatorios. SQL portable entre PostgreSQL y MySQL.
-- MigracionIT reaplica este fichero entero para comprobar que una segunda pasada no cambia nada.

-- 1. La app. Los puertos 5175 son fijos: la UI local usa ese puerto.
INSERT INTO auth_app
    (id, name, url, active, redirect_uris, post_logout_redirect_uris, access_ttl_seconds, created_at, updated_at)
SELECT 'a0000000-0000-4000-8000-000000000004', 'portales', 'https://portales.mobile-americas.com', TRUE,
       'https://portales.mobile-americas.com/callback,http://localhost:5175/callback',
       'https://portales.mobile-americas.com/,http://localhost:5175/',
       7200, TIMESTAMP '2026-11-11 00:00:00', TIMESTAMP '2026-11-11 00:00:00'
 WHERE NOT EXISTS (SELECT 1 FROM auth_app WHERE name = 'portales');

-- 2. El catalogo.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT n.id, a.id, n.resource, n.verb, NULL, TIMESTAMP '2026-11-11 00:00:00'
  FROM auth_app a
  JOIN (          SELECT 'b0000000-0000-4000-8000-000000000300' AS id, 'portales' AS resource, 'crear' AS verb
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000301', 'portales', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000302', 'portales', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000303', 'contenidos', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000304', 'contenidos', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000305', 'contenidos', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000306', 'contenidos', 'borrar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000307', 'categorias', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000308', 'categorias', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000309', 'categorias', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030a', 'categorias', 'borrar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030b', 'temas', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030c', 'temas', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030d', 'temas', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030e', 'temas', 'borrar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000030f', 'destacados', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000310', 'destacados', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000311', 'planes', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000312', 'planes', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000313', 'planes', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000314', 'planes', 'borrar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000315', 'logros', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000316', 'logros', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000317', 'logros', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000318', 'logros', 'borrar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000319', 'uso', 'leer'
       ) n ON 1 = 1
 WHERE a.name = 'portales'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p
                    WHERE p.app_id = a.id AND p.resource = n.resource AND p.verb = n.verb);

-- 3. Los roles.
INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-00000000000d', 'portales_contenidos', a.id,
       'Opera los contenidos de los portales: crea, edita y archiva contenidos y gestiona los destacados; categorias, temas, planes, logros y uso, solo lectura.',
       TIMESTAMP '2026-11-11 00:00:00', TIMESTAMP '2026-11-11 00:00:00'
  FROM auth_app a
 WHERE a.name = 'portales'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'portales_contenidos');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-00000000000e', 'portales_configuracion', a.id,
       'Configura los portales: da de alta y edita portales, y gestiona categorias, temas, planes y logros; contenidos, destacados y uso, solo lectura.',
       TIMESTAMP '2026-11-11 00:00:00', TIMESTAMP '2026-11-11 00:00:00'
  FROM auth_app a
 WHERE a.name = 'portales'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'portales_configuracion');

-- 4. Sus concesiones, explicitas.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'portales'
   AND r.name = 'portales_contenidos'
   AND ((p.resource = 'portales' AND p.verb = 'leer')
     OR (p.resource = 'contenidos' AND p.verb IN ('crear', 'leer', 'editar', 'borrar'))
     OR (p.resource = 'destacados' AND p.verb IN ('leer', 'editar'))
     OR (p.resource = 'categorias' AND p.verb = 'leer')
     OR (p.resource = 'temas' AND p.verb = 'leer')
     OR (p.resource = 'planes' AND p.verb = 'leer')
     OR (p.resource = 'logros' AND p.verb = 'leer')
     OR (p.resource = 'uso' AND p.verb = 'leer'))
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);

INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'portales'
   AND r.name = 'portales_configuracion'
   AND ((p.resource = 'portales' AND p.verb IN ('crear', 'leer', 'editar'))
     OR (p.resource = 'categorias' AND p.verb IN ('crear', 'leer', 'editar', 'borrar'))
     OR (p.resource = 'temas' AND p.verb IN ('crear', 'leer', 'editar', 'borrar'))
     OR (p.resource = 'planes' AND p.verb IN ('crear', 'leer', 'editar', 'borrar'))
     OR (p.resource = 'logros' AND p.verb IN ('crear', 'leer', 'editar', 'borrar'))
     OR (p.resource = 'contenidos' AND p.verb = 'leer')
     OR (p.resource = 'destacados' AND p.verb = 'leer')
     OR (p.resource = 'uso' AND p.verb = 'leer'))
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
