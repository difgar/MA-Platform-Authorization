package com.mobileamericas.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Infraestructura compartida por toda prueba de integración: solo el acceso a
 * la base de datos. Las pruebas propiamente dichas viven en las subclases
 * concretas (ver {@link MigracionIT} para las de migración).
 */
public abstract class BaseIT {

    @Autowired
    protected JdbcClient jdbc;
}
