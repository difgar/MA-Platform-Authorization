package com.mobileamericas.authorization.config;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

/**
 * La base de produccion (ma_auth en ma-platform-db-pgsql) es COMPARTIDA y exige el
 * conector de Cloud SQL (connectorEnforcement=REQUIRED): sin la socket factory, la URL
 * jdbc:postgresql:///ma_auth?cloudSqlInstance=... no conecta, y solo se veria al arrancar
 * en Cloud Run.
 */
class ConectorCloudSqlTest {

    @Test
    void la_socket_factory_de_cloud_sql_esta_en_el_classpath() {
        assertThatCode(() -> Class.forName("com.google.cloud.sql.postgres.SocketFactory"))
                .doesNotThrowAnyException();
    }
}
