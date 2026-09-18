-- ÚNICA migración por motor de todo el proyecto, y está justificada.
-- ATTRIBUTE_BYTES guarda atributos de sesión serializados: es genuinamente
-- binaria y no hay tipo con sintaxis común entre MySQL y PostgreSQL. No es
-- como los 'blob' del authorization server, que son de caracteres y admiten TEXT.
--
-- La regla de un solo juego de migraciones existe porque dos ficheros que deben
-- concordar sin que nada los compare son la forma del bug que mantuvo este
-- servicio caído. Aquí la suite de integración los compara en cada build,
-- ejecutando el flujo SSO completo contra los dos motores. Si algún día se deja
-- de probar uno, esta excepción deja de estar justificada.
CREATE TABLE SPRING_SESSION_ATTRIBUTES (
    SESSION_PRIMARY_ID CHAR(36)     NOT NULL,
    ATTRIBUTE_NAME     VARCHAR(200) NOT NULL,
    ATTRIBUTE_BYTES    BLOB         NOT NULL,
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
    CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID)
        REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
);
