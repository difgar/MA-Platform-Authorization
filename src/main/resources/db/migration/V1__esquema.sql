-- Un único juego de migraciones para MySQL 8 y PostgreSQL 17.
--
-- Solo se usan tipos que ambos motores aceptan con sintaxis idéntica:
-- VARCHAR, BIGINT, BOOLEAN, TIMESTAMP(6), TEXT.
--
-- Prohibidos aquí: AUTO_INCREMENT, GENERATED AS IDENTITY, JSON/jsonb, ENUM,
-- DEFAULT CHARSET= y ENGINE=. Las claves primarias son UUID generados en la
-- aplicación, que es lo que elimina el único constructo sin sintaxis común.
--
-- El juego de caracteres se fija al crear la base de datos (utf8mb4 en MySQL),
-- no por tabla: 'DEFAULT CHARSET=' rompería en PostgreSQL.

CREATE TABLE auth_app (
    id               VARCHAR(36)  NOT NULL,
    name             VARCHAR(100) NOT NULL,
    google_client_id VARCHAR(255) NOT NULL,
    url              VARCHAR(255),
    active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMP(6) NOT NULL,
    updated_at       TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_app PRIMARY KEY (id),
    CONSTRAINT uk_auth_app_name UNIQUE (name),
    CONSTRAINT uk_auth_app_google_client_id UNIQUE (google_client_id)
);

CREATE TABLE auth_permission (
    id          VARCHAR(36)  NOT NULL,
    app_id      VARCHAR(36)  NOT NULL,
    resource    VARCHAR(100) NOT NULL,
    verb        VARCHAR(20)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_permission PRIMARY KEY (id),
    CONSTRAINT uk_auth_permission UNIQUE (app_id, resource, verb),
    CONSTRAINT fk_auth_permission_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE TABLE auth_role (
    id          VARCHAR(36)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    app_id      VARCHAR(36)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP(6) NOT NULL,
    updated_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_role PRIMARY KEY (id),
    CONSTRAINT uk_auth_role_name_app UNIQUE (name, app_id),
    CONSTRAINT fk_auth_role_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE TABLE auth_user (
    id         VARCHAR(36)  NOT NULL,
    email      VARCHAR(320) NOT NULL,
    full_name  VARCHAR(255),
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_user PRIMARY KEY (id),
    CONSTRAINT uk_auth_user_email UNIQUE (email)
);

CREATE TABLE auth_user_role (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    CONSTRAINT pk_auth_user_role PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_auth_user_role_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_auth_user_role_role FOREIGN KEY (role_id) REFERENCES auth_role (id)
);

CREATE TABLE auth_role_permission (
    role_id       VARCHAR(36) NOT NULL,
    permission_id VARCHAR(36) NOT NULL,
    CONSTRAINT pk_auth_role_permission PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_auth_rp_role FOREIGN KEY (role_id) REFERENCES auth_role (id),
    CONSTRAINT fk_auth_rp_permission FOREIGN KEY (permission_id) REFERENCES auth_permission (id)
);

-- Se guarda el SHA-256 del token, nunca el token: un volcado de esta tabla no
-- permite suplantar a nadie. family_id agrupa las rotaciones sucesivas de una
-- misma sesión, para poder revocarlas todas si una se reutiliza.
CREATE TABLE auth_refresh_token (
    id         VARCHAR(36)  NOT NULL,
    user_id    VARCHAR(36)  NOT NULL,
    app_id     VARCHAR(36)  NOT NULL,
    token_hash VARCHAR(64)  NOT NULL,
    family_id  VARCHAR(36)  NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    used_at    TIMESTAMP(6),
    revoked_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_refresh_token PRIMARY KEY (id),
    CONSTRAINT uk_auth_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_auth_rt_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_auth_rt_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE INDEX ix_auth_refresh_token_family ON auth_refresh_token (family_id);

-- payload es TEXT y no JSON/jsonb a propósito: MySQL tiene JSON y PostgreSQL
-- tiene jsonb, y no son la misma sintaxis. Consultar dentro del payload sería
-- una migración específica por motor, consciente, no una sorpresa.
CREATE TABLE auth_audit (
    id          VARCHAR(36)  NOT NULL,
    actor_email VARCHAR(320) NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    entity      VARCHAR(50)  NOT NULL,
    entity_id   VARCHAR(36),
    payload     TEXT,
    created_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_audit PRIMARY KEY (id)
);

CREATE INDEX ix_auth_audit_created ON auth_audit (created_at);
