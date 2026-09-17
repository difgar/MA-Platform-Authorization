-- Reproduce el volcado de producción del 2026-09-16 (2 apps, 5 roles, 2
-- usuarios, 4 asignaciones usuario->rol) con equivalencia EXACTA de privilegios.
--
-- Los permisos antiguos eran verbos sueltos: view, read, create, update, delete.
-- view y read eran redundantes y colapsan en 'leer'. create, update y delete se
-- mantienen distinguibles como crear, editar y borrar: agruparlos en un único
-- 'escribir' le habría dado a support@admin un permiso de borrado que no tiene.
--
-- Los UUID van fijos y no generados: una migración debe producir el mismo
-- resultado en cada entorno donde se aplique.
--
-- Los google_client_id son marcadores. Se sustituyen por los reales con una
-- migración posterior o por el CRUD de la fase 2, NUNCA con el valor en git.

INSERT INTO auth_app (id, name, google_client_id, url, active, created_at, updated_at) VALUES
 ('a0000000-0000-4000-8000-000000000001', 'admin', 'PENDIENTE-admin', 'https://admin.mobile-americas.com', TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('a0000000-0000-4000-8000-000000000002', 'fgf',   'PENDIENTE-fgf',   'https://fgf.mobile-americas.com',   TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- Catálogo de recursos concretos. Es obligatorio: sin él, '*:*' expande a nada.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'apps',     'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001', 'apps',     'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000003', 'a0000000-0000-4000-8000-000000000001', 'apps',     'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000004', 'a0000000-0000-4000-8000-000000000001', 'apps',     'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000005', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000006', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000007', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000008', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000009', 'a0000000-0000-4000-8000-000000000001', 'roles',    'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000a', 'a0000000-0000-4000-8000-000000000001', 'roles',    'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000b', 'a0000000-0000-4000-8000-000000000001', 'roles',    'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000c', 'a0000000-0000-4000-8000-000000000001', 'roles',    'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000010', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000011', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000012', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000013', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00');

-- Comodines. Se expanden contra el catálogo de arriba al emitir el token.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-0000000000f1', 'a0000000-0000-4000-8000-000000000001', '*', '*',      'Todo en admin', TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f2', 'a0000000-0000-4000-8000-000000000001', '*', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f3', 'a0000000-0000-4000-8000-000000000001', '*', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f4', 'a0000000-0000-4000-8000-000000000002', '*', '*',      'Todo en fgf',   TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f5', 'a0000000-0000-4000-8000-000000000002', '*', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at) VALUES
 ('c0000000-0000-4000-8000-000000000001', 'admin',   'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000002', 'support', 'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000003', 'analyst', 'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000004', 'admin',   'a0000000-0000-4000-8000-000000000002', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000005', 'user',    'a0000000-0000-4000-8000-000000000002', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- admin@admin: view read create update delete -> *:*
-- support@admin: view read update             -> *:leer, *:editar
-- analyst@admin: view read                    -> *:leer
-- admin@fgf: view read create update delete   -> *:*
-- user@fgf: view                              -> *:leer
INSERT INTO auth_role_permission (role_id, permission_id) VALUES
 ('c0000000-0000-4000-8000-000000000001', 'b0000000-0000-4000-8000-0000000000f1'),
 ('c0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-0000000000f2'),
 ('c0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-0000000000f3'),
 ('c0000000-0000-4000-8000-000000000003', 'b0000000-0000-4000-8000-0000000000f2'),
 ('c0000000-0000-4000-8000-000000000004', 'b0000000-0000-4000-8000-0000000000f4'),
 ('c0000000-0000-4000-8000-000000000005', 'b0000000-0000-4000-8000-0000000000f5');

-- Los dos usuarios del volcado. Los emails reales se ponen con una migración
-- posterior o por el CRUD de la fase 2; aquí van marcadores para no meter datos
-- personales en git.
INSERT INTO auth_user (id, email, full_name, active, created_at, updated_at) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'usuario1@pendiente.local', NULL, TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('d0000000-0000-4000-8000-000000000002', 'usuario2@pendiente.local', NULL, TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- usuario1 -> admin@admin, user@fgf   ·   usuario2 -> analyst@admin, admin@fgf
INSERT INTO auth_user_role (user_id, role_id) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000005'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000003'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000004');
