-- Eliminar una campana de TrafficFlow: DELETE /api/v1/admin/campaigns/{id} (2026-11-23).
--
-- Es un borrado LOGICO (campaign.deleted_at): la fila se queda porque conversiones, clicks y
-- postbacks la referencian, y libera el keyword para otra campana del mismo servicio. Verbo
-- 'borrar', como 'reglas:borrar' y 'enlaces:borrar' (el verbo es un enum cerrado).
--
-- Quien lo recibe:
--   trafficflow_admin  : ya lo tiene, por el comodin '*:*' (V6).
--   trafficflow_user   : SE CONCEDE AQUI. Va sin comodin (V9), asi que un permiso nuevo del
--                        catalogo no le llega solo; puede crear y editar campanas, y eliminar
--                        es parte de configurarlas.
--   trafficflow_viewer : no ('*:leer').
--
-- POR NOMBRE Y NO POR ID, y cada sentencia solo actua si falta lo que crea, igual que V9..V13:
-- produccion se rehizo a mano con ids aleatorios. SQL portable entre PostgreSQL y MySQL.

-- 1. El permiso.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at)
SELECT 'b0000000-0000-4000-8000-00000000003a', a.id, 'campanas', 'borrar', NULL, TIMESTAMP '2026-11-23 00:00:00'
  FROM auth_app a
 WHERE a.name = 'trafficflow'
   AND NOT EXISTS (SELECT 1 FROM auth_permission p
                    WHERE p.app_id = a.id AND p.resource = 'campanas' AND p.verb = 'borrar');

-- 2. Concedido a trafficflow_user.
INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
  FROM auth_role r
  JOIN auth_app a ON a.id = r.app_id
  JOIN auth_permission p ON p.app_id = a.id
 WHERE a.name = 'trafficflow'
   AND r.name = 'trafficflow_user'
   AND p.resource = 'campanas' AND p.verb = 'borrar'
   AND NOT EXISTS (SELECT 1 FROM auth_role_permission x WHERE x.role_id = r.id AND x.permission_id = p.id);
