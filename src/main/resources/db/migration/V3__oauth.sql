-- Fase 2: el registro de clientes OAuth vive en auth_app, no en una tabla
-- aparte del framework. Dos registros que deben concordar sin que nada los
-- compare son la forma del bug que mantuvo este servicio caído.

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
-- timestamp van a TIMESTAMP(6) en ambos, y la exactitud se garantiza fijando
-- UTC en la JVM y en la conexión (ver application.yml y el deployment).
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
