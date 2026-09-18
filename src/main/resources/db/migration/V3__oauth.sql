-- Fase 2: el registro de clientes OAuth vive en auth_app, no en una tabla
-- aparte del framework. Dos registros que deben concordar sin que nada los
-- compare son la forma del bug que mantuvo este servicio caído.
--
-- El subconjunto portable que enuncia la cabecera de V1 (VARCHAR, BIGINT,
-- BOOLEAN, TIMESTAMP(6), TEXT) se queda corto para lo que sigue: CHAR(36),
-- usado en SPRING_SESSION más abajo, también es común a MySQL y PostgreSQL.
-- No se corrige la lista en V1 porque editarlo le cambiaría el checksum a
-- Flyway y rompería 'validate' en cualquier entorno donde ya se aplicó.
--
-- V2 dice, sobre google_client_id, que "se sustituyen por los reales con una
-- migración posterior o por el CRUD de la fase 2": esta migración es esa
-- posterior, y lo que hace con la columna es borrarla, no rellenarla. No se
-- corrige V2 por la misma razón que V1 -el checksum-, no porque la frase
-- siga siendo cierta cuando V2 corre.

ALTER TABLE auth_app ADD COLUMN redirect_uris TEXT;
ALTER TABLE auth_app ADD COLUMN post_logout_redirect_uris TEXT;
ALTER TABLE auth_app ADD COLUMN access_ttl_seconds BIGINT;

UPDATE auth_app SET
    redirect_uris = 'https://admin.mobile-americas.com/callback',
    post_logout_redirect_uris = 'https://admin.mobile-americas.com/',
    access_ttl_seconds = 7200
 WHERE name = 'admin';

UPDATE auth_app SET
    redirect_uris = 'https://fgf.mobile-americas.com/callback',
    post_logout_redirect_uris = 'https://fgf.mobile-americas.com/',
    access_ttl_seconds = 7200
 WHERE name = 'fgf';

-- La aplicación se deduce ahora del client_id de la petición, no del 'aud'
-- del token de Google: un solo cliente de Google para todo el servicio.
ALTER TABLE auth_app DROP COLUMN google_client_id;

-- La rotación y la detección de reutilización las hace el framework.
DROP TABLE auth_refresh_token;

-- Esquema del authorization server, portado al subconjunto portable.
-- Su DDL original usa 'blob' y 'timestamp'; su propia cabecera indica pasar
-- los blob a 'text' en PostgreSQL, porque son datos de caracteres. Los
-- timestamp van a TIMESTAMP(6) en ambos.
--
-- CONDICIÓN INSTALADA (tarea 9): usar TIMESTAMP(6) en vez de 'timestamptz'
-- sólo es seguro si la JVM y la conexión a MySQL están ancladas a UTC. Las dos
-- lo están ya, y en los tres sitios donde corre este esquema:
--   * el pod: TZ=UTC y -Duser.timezone=UTC en JAVA_TOOL_OPTIONS, más
--     preserveInstants/connectionTimeZone/forceConnectionTimeZoneToSession en
--     la URL de MySQL (kubernetes/deployment.yaml);
--   * el arranque local: systemProperty 'user.timezone' en bootRun
--     (build.gradle);
--   * la suite de integración: el mismo systemProperty en integrationTest.
-- Si alguno de esos tres anclajes desaparece, estos TIMESTAMP(6) vuelven a
-- depender de la zona del entorno y las caducidades se desplazan con ella.
CREATE TABLE oauth2_authorization (
    id                             VARCHAR(100)  NOT NULL,
    registered_client_id           VARCHAR(100)  NOT NULL,
    principal_name                 VARCHAR(200)  NOT NULL,
    authorization_grant_type       VARCHAR(100)  NOT NULL,
    authorized_scopes              VARCHAR(1000),
    attributes                     TEXT,
    state                          VARCHAR(500),
    authorization_code_value       TEXT,
    authorization_code_issued_at   TIMESTAMP(6),
    authorization_code_expires_at  TIMESTAMP(6),
    authorization_code_metadata    TEXT,
    access_token_value             TEXT,
    access_token_issued_at         TIMESTAMP(6),
    access_token_expires_at        TIMESTAMP(6),
    access_token_metadata          TEXT,
    access_token_type              VARCHAR(100),
    access_token_scopes            VARCHAR(1000),
    oidc_id_token_value            TEXT,
    oidc_id_token_issued_at        TIMESTAMP(6),
    oidc_id_token_expires_at       TIMESTAMP(6),
    oidc_id_token_metadata         TEXT,
    refresh_token_value            TEXT,
    refresh_token_issued_at        TIMESTAMP(6),
    refresh_token_expires_at       TIMESTAMP(6),
    refresh_token_metadata         TEXT,
    user_code_value                TEXT,
    user_code_issued_at            TIMESTAMP(6),
    user_code_expires_at           TIMESTAMP(6),
    user_code_metadata             TEXT,
    device_code_value              TEXT,
    device_code_issued_at          TIMESTAMP(6),
    device_code_expires_at         TIMESTAMP(6),
    device_code_metadata           TEXT,
    CONSTRAINT pk_oauth2_authorization PRIMARY KEY (id)
);

-- Sesión SSO. La tabla de atributos va aparte, por motor: ver V4.
-- MAX_INACTIVE_INTERVAL es BIGINT aquí y no INT como en el esquema oficial de
-- Spring Session: la lista de tipos portables de esta fase no incluye INT.
-- Es seguro de todos modos porque JdbcIndexedSessionRepository lo lee con
-- ResultSet.getInt(...), que funciona igual sobre una columna más ancha.
CREATE TABLE SPRING_SESSION (
    PRIMARY_ID            CHAR(36) NOT NULL,
    SESSION_ID            CHAR(36) NOT NULL,
    CREATION_TIME         BIGINT   NOT NULL,
    LAST_ACCESS_TIME      BIGINT   NOT NULL,
    MAX_INACTIVE_INTERVAL BIGINT   NOT NULL,
    EXPIRY_TIME           BIGINT   NOT NULL,
    PRINCIPAL_NAME        VARCHAR(100),
    CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);

CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);
