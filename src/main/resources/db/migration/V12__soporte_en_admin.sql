-- El modulo Soporte del admin (2026-10-30): sus recursos en el catalogo de la app 'admin' y el
-- rol 'soporte' (spec: MA-Platform-config/docs/specs/2026-10-30-modulo-soporte-design.md).
--
-- Tres permisos, los que comprueba MA-Platform-Support-API:
--   soporte:leer         consultar una linea: suscripciones, blacklist, solicitudes y texto para Claro
--   cancelaciones:crear  pedir a Claro la baja de una suscripcion
--   blacklist:editar     agregar una linea a la blacklist o quitarla
--
-- La spec decia 'soporte:cancelar'. 'cancelar' NO es un verbo del dominio: Verb es un enum cerrado
-- (crear, leer, editar, borrar) y DomainMapper construye un Permission por fila, asi que una fila
-- con verbo 'cancelar' haria fallar la carga del rol (y el login de quien lo tenga). Mismo caso
-- que 'postbacks:reenviar' en V5: recurso propio y verbo 'crear' (POST .../cancelacion crea una
-- cancelacion). MigracionIT comprueba que todas las filas son permisos validos.
--
-- El 'admin' ('*:*') los obtiene sin tocarlo: el catalogo del admin pasa de 11 a 14 recursos y
-- su token de 44 a 56 permisos (AccessGrant expande RECURSOS x VERBOS, no filas). Ojo: en una base
-- nueva, V2 crea 'support' (*:leer, *:editar), que por la misma expansion tendria soporte:leer y
-- blacklist:editar. En produccion 'support' no existe (comprobado el 2026-10-29). 'soporte' y
-- 'support' son roles distintos. Asignar 'soporte' a una persona sigue siendo a mano.
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea, igual que V9..V11:
-- produccion se rehizo a mano con ids aleatorios. SQL portable entre PostgreSQL y MySQL.
-- MigracionIT reaplica este fichero entero para comprobar que una segunda pasada no cambia nada.

-- 1. El catalogo.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT n.id, a.id, n.resource, n.verb, NULL, TIMESTAMP '2026-10-30 00:00:00'
  FROM auth_app a
  JOIN (          SELECT 'b0000000-0000-4000-8000-000000000215' AS id, 'soporte'       AS resource, 'leer'   AS verb
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000216', 'cancelaciones', 'crear'
        UNION ALL SELECT 'b0000000-0000-4000-8000-000000000217', 'blacklist',     'editar'
       ) n ON 1 = 1
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p
                    WHERE p.app_id = a.id AND p.resource = n.resource AND p.verb = n.verb);

-- 2. El rol.
INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at)
SELECT 'c0000000-0000-4000-8000-00000000000c', 'soporte', a.id,
       'Atiende los reclamos de una linea desde el admin: consulta, pide a Claro la baja de una suscripcion y agrega o quita la linea de la blacklist.',
       TIMESTAMP '2026-10-30 00:00:00', TIMESTAMP '2026-10-30 00:00:00'
  FROM auth_app a
 WHERE a.name = 'admin'
   AND NOT EXISTS (SELECT 1 FROM auth_role r WHERE r.app_id = a.id AND r.name = 'soporte');

-- 3. Sus concesiones: los tres permisos del modulo.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'admin'
   AND r.name = 'soporte'
   AND ((p.resource = 'soporte' AND p.verb = 'leer')
     OR (p.resource = 'cancelaciones' AND p.verb = 'crear')
     OR (p.resource = 'blacklist' AND p.verb = 'editar'))
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
