package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pruebas de migración. Cada motor la extiende con su contenedor y su propio
 * {@code @SpringBootTest} (ver las clases concretas).
 *
 * La misma suite se ejecuta contra MySQL y contra PostgreSQL: es lo que convierte
 * "agnóstico del motor" en un hecho que verifica el build y no en una promesa.
 */
public abstract class MigracionIT extends BaseIT {

    private long contar(String tabla) {
        return jdbc.sql("SELECT count(*) FROM " + tabla).query(Long.class).single();
    }

    @Test
    void las_migraciones_crean_las_tablas_esperadas() {
        var tablas = jdbc.sql("""
                        SELECT table_name FROM information_schema.tables
                         WHERE table_schema NOT IN ('pg_catalog','information_schema','sys','mysql','performance_schema')
                        """)
                .query(String.class).list().stream().map(String::toLowerCase).toList();

        assertThat(tablas).contains(
                "auth_app", "auth_permission", "auth_role", "auth_user",
                "auth_user_role", "auth_role_permission", "auth_audit",
                "oauth2_authorization", "spring_session", "spring_session_attributes");
        assertThat(tablas).doesNotContain("auth_refresh_token");
    }

    @Test
    void auth_app_lleva_la_configuracion_de_cliente_oauth() {
        var cols = jdbc.sql("""
                        SELECT column_name FROM information_schema.columns
                         WHERE lower(table_name) = 'auth_app'
                        """).query(String.class).list().stream().map(String::toLowerCase).toList();

        assertThat(cols).contains("redirect_uris", "post_logout_redirect_uris", "access_ttl_seconds");
        assertThat(cols).doesNotContain("google_client_id");
    }

    @Test
    void reproduce_el_volcado_de_produccion() {
        assertThat(contar("auth_app")).isEqualTo(2L);
        assertThat(contar("auth_user")).isEqualTo(2L);
        assertThat(contar("auth_role")).isEqualTo(5L);
        assertThat(contar("auth_user_role")).isEqualTo(4L);
    }

    @Test
    void support_conserva_exactamente_sus_privilegios() {
        // view, read, update -> *:leer y *:editar. Ni crear ni borrar.
        var permisos = jdbc.sql("""
                        SELECT p.resource, p.verb FROM auth_permission p
                          JOIN auth_role_permission rp ON rp.permission_id = p.id
                          JOIN auth_role r ON r.id = rp.role_id
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE r.name = 'support' AND a.name = 'admin'
                        """)
                .query((rs, n) -> rs.getString("resource") + ":" + rs.getString("verb"))
                .list();

        assertThat(permisos).containsExactlyInAnyOrder("*:leer", "*:editar");
    }

    @Test
    void cada_app_declara_un_catalogo_de_recursos_concretos() {
        // Sin recursos concretos, '*:*' expandiría a nada (ver AccessGrantTest).
        var apps = jdbc.sql("""
                        SELECT a.name FROM auth_app a
                         WHERE NOT EXISTS (
                           SELECT 1 FROM auth_permission p
                            WHERE p.app_id = a.id AND p.resource <> '*')
                        """).query(String.class).list();

        assertThat(apps).as("apps sin catálogo de recursos").isEmpty();
    }
}
