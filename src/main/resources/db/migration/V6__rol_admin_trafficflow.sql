-- El rol de administrador de trafficflow, con comodín.
--
-- Es una DECISIÓN, no el resultado de no haber decidido: difgar la tomó con la
-- consecuencia delante ("ok sí, lo veremos funcionando y luego veo si se cambia
-- algo"). Se deja escrita porque el comodín concede TODO el catálogo de la
-- aplicación, y en el de trafficflow hay un permiso que no es como los demás.
--
-- La advertencia va en auth_role.description, no sólo en este comentario, por
-- dos razones: se puede cambiar con un UPDATE cuando se afine el reparto, sin
-- tocar migraciones; y cuando exista el CRUD de administración la leerá quien
-- reparta roles, que es justo quien tiene que enterarse antes de concederlo.
--
-- Y el comodín no admite exclusiones: AccessGrant expande '*:*' contra todo el
-- catálogo y hace la UNIÓN de lo que conceden los roles. No hay permiso
-- negativo. Para que este rol NO incluyera reenvios:crear habría que enumerar
-- los otros 24 y perder el comodín para siempre, con el precio de que cada
-- permiso nuevo habría que acordarse de añadirlo aquí.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-0000000000f6', 'a0000000-0000-4000-8000-000000000003', '*', '*', 'Todo en trafficflow', TIMESTAMP '2026-09-19 00:00:00');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at) VALUES
 ('c0000000-0000-4000-8000-000000000006', 'admin', 'a0000000-0000-4000-8000-000000000003',
  'Administra TrafficFlow. Incluye reenviar una notificacion de conversion: reportar la misma conversion dos veces se paga dos veces, y el pago es nuestro porque la red es el afiliado. El efecto ocurre en el sistema de un tercero y no se puede deshacer.',
  TIMESTAMP '2026-09-19 00:00:00', TIMESTAMP '2026-09-19 00:00:00');

INSERT INTO auth_role_permission (role_id, permission_id) VALUES
 ('c0000000-0000-4000-8000-000000000006', 'b0000000-0000-4000-8000-0000000000f6');

-- Sin asignar a nadie: los usuarios reales no entran en git. V2 siembra
-- usuario1/usuario2 con dominio @pendiente.local precisamente para que ningun
-- correo real viaje en una migracion, y el alta de personas concretas se hace
-- en cada entorno.
