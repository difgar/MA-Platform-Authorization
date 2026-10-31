-- El admin de configuracion (2026-10-29): sus recursos en el catalogo de la app 'admin' y el
-- rol 'configurador' (spec: MA-Platform-config/docs/specs/2026-10-29-admin-configuracion-design.md).
--
-- Los recursos son las tablas de configuracion de ma_platform que edita MA-Platform-Config-API.
-- Ninguno lleva 'borrar': en la configuracion no se borra, se inhabilita (enabled = false).
-- catalogos (operadoras, periodos, eventos) solo se leen; bigquery solo se "edita" (lanzar la
-- sincronizacion).
--
-- El 'admin' del admin ('*:*') los obtiene sin tocarlo: el comodin se expande contra este
-- catalogo. OJO: AccessGrant expande RECURSOS x VERBOS, no filas: el admin recibe tambien
-- combinaciones que no existen como fila (p. ej. 'servicios:borrar', 'catalogos:crear').
-- Es aceptable: ningun endpoint de la Config-API las comprueba. Asignar 'configurador' a una
-- persona sigue siendo a mano (los correos reales no entran en git, ver el final de V6).
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea, igual que V9 y V10:
-- produccion se rehizo a mano con ids aleatorios. SQL portable entre PostgreSQL y MySQL.
-- MigracionIT reaplica este fichero entero para comprobar que una segunda pasada no cambia nada.

-- 1. El catalogo.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT n.id, a.id, n.resource, n.verb, NULL, TIMESTAMP '2026-10-29 00:00:00'
  FROM auth_app a
  JOIN (          SELECT 'b0000000-0000-4000-8000-000000000201' AS id, 'servicios' AS resource, 'leer' AS verb
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000202', 'servicios', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000203', 'servicios', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000204', 'configuraciones', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000205', 'configuraciones', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000206', 'configuraciones', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000207', 'callbacks', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000208', 'callbacks', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000209', 'callbacks', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020a', 'mapeos', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020b', 'mapeos', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020c', 'mapeos', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020d', 'mensajeria', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020e', 'mensajeria', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-00000000020f', 'mensajeria', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000210', 'anuncios', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000211', 'anuncios', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000212', 'anuncios', 'editar'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000213', 'catalogos', 'leer'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000214', 'bigquery', 'editar'
       ) n ON 1 = 1
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p
                    WHERE p.app_id = a.id AND p.resource = n.resource AND p.verb = n.verb);

-- 2. El rol.
INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-00000000000b', 'configurador', a.id,
       'Edita la configuracion de la plataforma (servicios, callbacks, mapeos, mensajeria, anuncios) desde el admin. No borra: inhabilita.',
       TIMESTAMP '2026-10-29 00:00:00', TIMESTAMP '2026-10-29 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'configurador');

-- 3. Sus concesiones: todo el catalogo de configuracion.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'admin'
   AND r.name = 'configurador'
   AND p.resource IN ('servicios', 'configuraciones', 'callbacks', 'mapeos', 'mensajeria', 'anuncios', 'catalogos', 'bigquery')
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
