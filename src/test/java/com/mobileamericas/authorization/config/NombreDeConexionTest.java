package com.mobileamericas.authorization.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;

/**
 * En la base compartida (50 conexiones para tres proyectos) cada conexion dice de quien
 * es en pg_stat_activity: ma-platform-auth/<revision de Cloud Run>. PostgreSQL trunca
 * application_name a 63 sin avisar; se recorta aqui igual para que lo configurado y lo
 * visto coincidan. Misma convencion que MA-Portal y TrafficFlow.
 */
class NombreDeConexionTest {

    private final NombreDeConexion recortador = new NombreDeConexion();

    @Test
    void recorta_a_63_caracteres_un_nombre_largo() {
        var ds = new HikariDataSource();
        ds.addDataSourceProperty("ApplicationName", "ma-platform-auth/" + "x".repeat(80));

        recortador.postProcessAfterInitialization(ds, "dataSource");

        assertThat((String) ds.getDataSourceProperties().get("ApplicationName"))
                .hasSize(63).startsWith("ma-platform-auth/");
    }

    @Test
    void deja_igual_un_nombre_corto() {
        var ds = new HikariDataSource();
        ds.addDataSourceProperty("ApplicationName", "ma-platform-auth/ma-authorization-00001-abc");

        recortador.postProcessAfterInitialization(ds, "dataSource");

        assertThat(ds.getDataSourceProperties().get("ApplicationName"))
                .isEqualTo("ma-platform-auth/ma-authorization-00001-abc");
    }
}
