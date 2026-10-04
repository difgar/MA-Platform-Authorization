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
-- catalogo de 26 menos reenvios:crear (b...34) y barridos:crear (b...39), las dos acciones
-- que hacen salir un postback hacia la red, y el pago es nuestro. El precio, escrito en la
-- descripcion del rol: un permiso nuevo del catalogo NO le llega solo; hay que concederlo
-- en la migracion que lo cree.

UPDATE auth_role
   SET name = 'trafficflow_admin', updated_at = TIMESTAMP '2026-10-04 00:00:00'
 WHERE id = 'c0000000-0000-4000-8000-000000000006';

INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-0000000000f7', 'a0000000-0000-4000-8000-000000000003', '*', 'leer', 'Leer todo en trafficflow', TIMESTAMP '2026-10-04 00:00:00');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at) VALUES
 ('c0000000-0000-4000-8000-000000000007', 'trafficflow_user', 'a0000000-0000-4000-8000-000000000003',
  'Configura TrafficFlow (redes, servicios, campanas, enlaces, reglas, endpoints) y lo ve todo, pero no reenvia ni barre postbacks. Sin comodin: cada permiso nuevo del catalogo hay que concederselo a mano.',
  TIMESTAMP '2026-10-04 00:00:00', TIMESTAMP '2026-10-04 00:00:00'),
 ('c0000000-0000-4000-8000-000000000008', 'trafficflow_viewer', 'a0000000-0000-4000-8000-000000000003',
  'Solo lectura de TrafficFlow.',
  TIMESTAMP '2026-10-04 00:00:00', TIMESTAMP '2026-10-04 00:00:00');

INSERT INTO auth_role_permission (role_id, permission_id) VALUES
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000020'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000021'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000022'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000023'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000024'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000025'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000026'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000027'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000028'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000029'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002a'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002b'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002c'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002d'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002e'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-00000000002f'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000030'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000031'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000032'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000033'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000035'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000036'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000037'),
 ('c0000000-0000-4000-8000-000000000007', 'b0000000-0000-4000-8000-000000000038'),
 ('c0000000-0000-4000-8000-000000000008', 'b0000000-0000-4000-8000-0000000000f7');
