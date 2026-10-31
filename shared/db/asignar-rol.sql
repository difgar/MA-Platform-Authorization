-- Da a una persona un rol de la app `admin` (configurador, soporte...). Idempotente: si ya lo
-- tiene no hace nada. La persona tiene que existir y estar activa (haber entrado al menos una vez
-- o estar en usuarios.sql): este script no crea usuarios.
--
-- Se ejecuta como ma_auth sobre la base ma_auth, por el proxy (CONNECTION LIMIT 6: con DBeaver
-- conectado como ma_auth puede no haber sitio):
--   cloud-sql-proxy sms-ma-platform:us-east1:ma-platform-db-pgsql --port 15441 --gcloud-auth
--   PGPASSWORD="$(gcloud secrets versions access latest --secret=ma-auth-db-password --project=sms-ma-platform)" \
--     psql "host=127.0.0.1 port=15441 dbname=ma_auth user=ma_auth sslmode=disable" -v ON_ERROR_STOP=1 \
--          -v email=difgar@gmail.com -v rol=soporte -f shared/db/asignar-rol.sql
-- El rol entra en el SIGUIENTE token: la persona tiene que salir y volver a entrar al admin.
--
-- Deshacer (mismas variables):
--   DELETE FROM auth_user_role
--    WHERE user_id = (SELECT id FROM auth_user WHERE email = lower(:'email'))
--      AND role_id = (SELECT r.id FROM auth_role r JOIN auth_app a ON a.id = r.app_id
--                      WHERE a.name = 'admin' AND r.name = :'rol');
\if :{?email}
\else
  \echo 'Falta -v email=...'
  \quit
\endif
\if :{?rol}
\else
  \echo 'Falta -v rol=...'
  \quit
\endif

SELECT EXISTS (SELECT 1 FROM auth_user WHERE email = lower(:'email') AND active) AS hay_usuario,
       EXISTS (SELECT 1 FROM auth_role r JOIN auth_app a ON a.id = r.app_id
                WHERE a.name = 'admin' AND r.name = :'rol') AS hay_rol \gset
\if :hay_usuario
\else
  \echo 'No hay un usuario activo con ese email: que entre una vez al admin, o revisar el email.'
  SELECT 1 / 0 AS sin_usuario;
\endif
\if :hay_rol
\else
  \echo 'La app admin no tiene ese rol (¿V11/V12 aplicadas? ¿errata?).'
  SELECT 1 / 0 AS sin_rol;
\endif

INSERT INTO auth_user_role (user_id, role_id)
SELECT u.id, r.id
  FROM auth_user u
  JOIN auth_role r ON r.name = :'rol'
  JOIN auth_app a ON a.id = r.app_id AND a.name = 'admin'
 WHERE u.email = lower(:'email')
   AND NOT EXISTS (SELECT 1 FROM auth_user_role x WHERE x.user_id = u.id AND x.role_id = r.id);

SELECT u.email, a.name AS app, r.name AS rol
  FROM auth_user u
  JOIN auth_user_role ur ON ur.user_id = u.id
  JOIN auth_role r ON r.id = ur.role_id
  JOIN auth_app a ON a.id = r.app_id
 WHERE u.email = lower(:'email')
 ORDER BY a.name, r.name;
