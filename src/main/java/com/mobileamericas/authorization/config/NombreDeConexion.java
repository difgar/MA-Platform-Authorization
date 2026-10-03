package com.mobileamericas.authorization.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * Recorta el {@code ApplicationName} de las conexiones a los 63 caracteres que guarda
 * PostgreSQL (NAMEDATALEN - 1). PostgreSQL lo trunca sin avisar; recortarlo aqui hace que
 * lo configurado y lo que se ve en {@code pg_stat_activity} sean lo mismo.
 *
 * <p>Importa porque ma-platform-db-pgsql es compartida y tiene 50 conexiones para todos:
 * el nombre es como se sabe quien consume cada una. Misma convencion que MA-Portal y
 * TrafficFlow: {@code <aplicacion>/<revision de Cloud Run>}.
 */
@Component
class NombreDeConexion implements BeanPostProcessor {

    static final int MAXIMO_DE_POSTGRESQL = 63;

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof HikariDataSource hikari
                && hikari.getDataSourceProperties().get("ApplicationName") instanceof String nombre
                && nombre.length() > MAXIMO_DE_POSTGRESQL) {
            hikari.addDataSourceProperty("ApplicationName", nombre.substring(0, MAXIMO_DE_POSTGRESQL));
        }
        return bean;
    }
}
