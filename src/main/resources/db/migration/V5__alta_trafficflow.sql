-- Da de alta la tercera aplicación, trafficflow, con su catálogo de permisos.
-- Es una migración y no una fila metida a mano por la misma razón que motivó
-- la fase 2: dos registros que deben concordar sin que nada los compare -la
-- tabla de esta app y la tabla del framework- es la forma exacta del bug que
-- mantuvo este servicio caído en producción, y una migración es lo único que
-- deja el mismo resultado en cada entorno donde se aplique.
--
-- Sigue el subconjunto portable de la cabecera de V1 y los UUID literales de
-- V2: nada de AUTO_INCREMENT, GENERATED AS IDENTITY, JSON/jsonb, ENUM,
-- DEFAULT CHARSET= ni ENGINE=.
--
-- Los dos puertos 5174 (redirect_uris y post_logout_redirect_uris) son fijos:
-- el vite.config.ts de TrafficFlow fija port: 5174 con strictPort: true.
INSERT INTO auth_app
    (id, name, url, active, redirect_uris, post_logout_redirect_uris, access_ttl_seconds, created_at, updated_at)
VALUES
    ('a0000000-0000-4000-8000-000000000003', 'trafficflow', 'https://tf.mobile-americas.com', TRUE,
     'https://tf.mobile-americas.com/callback,http://localhost:5174/callback',
     'https://tf.mobile-americas.com/,http://localhost:5174/',
     7200, TIMESTAMP '2026-09-19 00:00:00', TIMESTAMP '2026-09-19 00:00:00');

-- Catálogo de recursos concretos, derivado de las 37 operaciones del contrato
-- OpenAPI de TrafficFlow. 25 exactos: ni uno de más ni uno de menos.
--
-- redes, servicios y campanas NO llevan 'borrar': su API no tiene endpoint de
-- borrado para esos recursos.
--
-- enlaces:borrar es el 'revoke' del enlace, mapeado a 'borrar' por su
-- consecuencia -corta el tráfico de ese enlace para siempre-, no por su verbo
-- HTTP (el endpoint es un POST).
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-000000000020', 'a0000000-0000-4000-8000-000000000003', 'redes',      'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000021', 'a0000000-0000-4000-8000-000000000003', 'redes',      'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000022', 'a0000000-0000-4000-8000-000000000003', 'redes',      'editar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000023', 'a0000000-0000-4000-8000-000000000003', 'servicios',  'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000024', 'a0000000-0000-4000-8000-000000000003', 'servicios',  'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000025', 'a0000000-0000-4000-8000-000000000003', 'servicios',  'editar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000026', 'a0000000-0000-4000-8000-000000000003', 'campanas',   'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000027', 'a0000000-0000-4000-8000-000000000003', 'campanas',   'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000028', 'a0000000-0000-4000-8000-000000000003', 'campanas',   'editar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000029', 'a0000000-0000-4000-8000-000000000003', 'enlaces',    'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002a', 'a0000000-0000-4000-8000-000000000003', 'enlaces',    'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002b', 'a0000000-0000-4000-8000-000000000003', 'enlaces',    'borrar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002c', 'a0000000-0000-4000-8000-000000000003', 'reglas',     'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002d', 'a0000000-0000-4000-8000-000000000003', 'reglas',     'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002e', 'a0000000-0000-4000-8000-000000000003', 'reglas',     'editar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-00000000002f', 'a0000000-0000-4000-8000-000000000003', 'reglas',     'borrar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000030', 'a0000000-0000-4000-8000-000000000003', 'endpoints',  'crear',  NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000031', 'a0000000-0000-4000-8000-000000000003', 'endpoints',  'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000032', 'a0000000-0000-4000-8000-000000000003', 'endpoints',  'editar', NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000033', 'a0000000-0000-4000-8000-000000000003', 'postbacks',  'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000035', 'a0000000-0000-4000-8000-000000000003', 'informe',    'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000036', 'a0000000-0000-4000-8000-000000000003', 'auditoria',  'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000037', 'a0000000-0000-4000-8000-000000000003', 'cache',      'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00'),
 ('b0000000-0000-4000-8000-000000000038', 'a0000000-0000-4000-8000-000000000003', 'busqueda',   'leer',   NULL, TIMESTAMP '2026-09-19 00:00:00');

-- 'postbacks:reenviar' NO se registra así: 'reenviar' no es un verbo del
-- dominio y no se va a añadir. Verb es un enum cerrado (crear, leer, editar,
-- borrar) y AccessGrant.expandir expande el comodín usando TODOS los verbos
-- contra el catálogo de CADA aplicación, así que un verbo nuevo metería
-- 'apps:reenviar', 'usuarios:reenviar' y demás en los tokens de todas las
-- aplicaciones, para siempre.
--
-- Se registra como recurso propio -'reenvios', verbo 'crear'-, que además es
-- la lectura honesta del endpoint: un POST /postbacks/{id}/resend crea un
-- reenvío.
--
-- Reenviar una notificación de conversión reporta la misma conversión dos
-- veces, y cada conversión reportada se paga. El efecto ocurre en el sistema
-- de la red y no se puede deshacer desde aquí.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-000000000034', 'a0000000-0000-4000-8000-000000000003', 'reenvios', 'crear', NULL, TIMESTAMP '2026-09-19 00:00:00');

-- Sin roles todavía, a propósito: difgar tiene pendiente decidir si el
-- administrador de trafficflow lleva comodín. Mientras no haya roles, quien
-- pida un token para trafficflow recibe access_denied, que es correcto.
