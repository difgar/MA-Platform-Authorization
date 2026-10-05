package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.util.List;

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
        // count(*) sobre una tabla concreta es tautológico para esta pregunta:
        // si la tabla no existiera la consulta ni siquiera compilaría, así que
        // no distingue "está de más" de "falta". information_schema.tables sí
        // lo hace, y funciona igual en los dos motores excluyendo sus catálogos
        // de sistema: pg_catalog e information_schema son los de PostgreSQL;
        // sys, mysql y performance_schema son los de MySQL.
        // containsExactlyInAnyOrder (no contains): una tabla de más -por
        // ejemplo, oauth2_authorization_consent creada por error- debe hacer
        // fallar esta prueba tanto como una de menos.
        var tablas = jdbc.sql("""
                        SELECT table_name FROM information_schema.tables
                         WHERE table_schema NOT IN ('pg_catalog','information_schema','sys','mysql','performance_schema')
                        """)
                .query(String.class).list().stream().map(String::toLowerCase).toList();

        assertThat(tablas).containsExactlyInAnyOrder(
                "auth_app", "auth_permission", "auth_role", "auth_user",
                "auth_user_role", "auth_role_permission", "auth_audit",
                "oauth2_authorization", "spring_session", "spring_session_attributes",
                "flyway_schema_history");
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

    private record ConfiguracionCliente(
            String redirectUris, String postLogoutRedirectUris, long accessTtlSeconds) {}

    private ConfiguracionCliente configuracionCliente(String appName) {
        return jdbc.sql("""
                        SELECT redirect_uris, post_logout_redirect_uris, access_ttl_seconds
                          FROM auth_app WHERE name = :nombre
                        """)
                .param("nombre", appName)
                .query((rs, n) -> new ConfiguracionCliente(
                        rs.getString("redirect_uris"),
                        rs.getString("post_logout_redirect_uris"),
                        rs.getLong("access_ttl_seconds")))
                .single();
    }

    @Test
    void auth_app_lleva_los_valores_sembrados_de_cada_cliente() {
        // Una errata en una URL o en el TTL sembrados aquí no rompe nada en esta
        // tarea: aparecería tres tareas más tarde como un redirect_uri_mismatch
        // desconcertante en la 4, o un token que vive de más o de menos en la 8.
        // Esta prueba la ata a su causa.
        var admin = configuracionCliente("admin");
        assertThat(admin.redirectUris()).isEqualTo("https://admin.mobile-americas.com/callback");
        assertThat(admin.postLogoutRedirectUris()).isEqualTo("https://admin.mobile-americas.com/");
        assertThat(admin.accessTtlSeconds()).isEqualTo(7200L);

        var fgf = configuracionCliente("fgf");
        assertThat(fgf.redirectUris()).isEqualTo("https://fgf.mobile-americas.com/callback");
        assertThat(fgf.postLogoutRedirectUris()).isEqualTo("https://fgf.mobile-americas.com/");
        assertThat(fgf.accessTtlSeconds()).isEqualTo(7200L);
    }

    @Test
    void oauth2_authorization_tiene_las_treintaitres_columnas_del_authorization_server() {
        // Sin esto, la prueba de arriba en las_migraciones_crean_las_tablas_esperadas
        // pasa con la tabla creada a medias: existir no es lo mismo que tener el
        // esquema completo que JdbcOAuth2AuthorizationService espera.
        //
        // OJO: ese servicio NO está declarado hoy como bean, así que esta tabla
        // está creada y vacía y nadie la escribe (el almacén en uso es el de
        // memoria). Esta prueba afirma que el porte del esquema es correcto,
        // no que se esté usando. Ver README, sección «Réplicas».
        var columnas = jdbc.sql("""
                        SELECT count(*) FROM information_schema.columns
                         WHERE lower(table_name) = 'oauth2_authorization'
                        """).query(Long.class).single();

        assertThat(columnas).isEqualTo(33L);
    }

    @Test
    void reproduce_el_volcado_de_produccion() {
        // auth_app pasa de 2 a 3 con V5__alta_trafficflow.sql y auth_role de 5 a
        // 6 con V6__rol_admin_trafficflow.sql, y a 8 con V9__roles_de_trafficflow.sql
        // (trafficflow_user y trafficflow_viewer), y a 9 con V10__rol_admin_user_en_admin.sql
        // (usuario@admin, la puerta al menú de aplicaciones). auth_user y auth_user_role NO
        // cambian: ninguna migración da de alta personas ni les asigna roles,
        // porque los correos reales no entran en git (ver el final de V6).
        assertThat(contar("auth_app")).isEqualTo(3L);
        assertThat(contar("auth_user")).isEqualTo(2L);
        assertThat(contar("auth_role")).isEqualTo(9L);
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
    void el_rol_admin_user_del_admin_solo_deja_ver_el_menu_de_aplicaciones() {
        // V10 (2026-10-05): quien sólo usa TrafficFlow (finanzas@) entraba por el admin
        // -el menú desde el que se salta a cada aplicación- y era rechazado por sin_rol,
        // porque no tenía NINGÚN rol en admin. Este rol es la puerta mínima: apps:leer y
        // nada más. Ni usuarios ni roles, ni crear ni editar apps.
        assertThat(permisosDelRolEn("admin", "admin_user")).containsExactly("apps:leer");
    }

    @Test
    void el_rol_admin_user_del_admin_explica_para_que_es() {
        // La descripción es lo que ve quien asigna roles desde el propio admin: sin ella,
        // 'admin_user' parece un rol genérico del admin y no la puerta al menú.
        var descripcion = jdbc.sql("""
                        SELECT r.description FROM auth_role r JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = 'admin' AND r.name = 'admin_user'
                        """).query(String.class).single();

        assertThat(descripcion).contains("menu").contains("apps:leer");
    }

    @Test
    void el_admin_del_admin_sigue_con_el_comodin() {
        // Producción lo tiene creado a mano; V2 lo trae en una base nueva. V10 lo asegura
        // por nombre sin duplicarlo: exactamente uno, con '*:*'.
        assertThat(permisosDelRolEn("admin", "admin")).containsExactly("*:*");
    }

    @Test
    void v10_es_idempotente_y_reaplicarla_no_cambia_nada() {
        // Producción se rehizo a mano con ids aleatorios y YA puede traer parte de lo que V10
        // crea: cada sentencia tiene que no hacer nada si lo suyo ya está. Reaplicar el mismo
        // fichero sobre una base que ya lo tiene es la forma de comprobarlo sin una copia de
        // producción.
        var rolesAntes = contar("auth_role");
        var permisosAntes = contar("auth_permission");
        var concesionesAntes = contar("auth_role_permission");

        new ResourceDatabasePopulator(new ClassPathResource("db/migration/V10__rol_admin_user_en_admin.sql"))
                .execute(fuente);

        assertThat(contar("auth_role")).isEqualTo(rolesAntes);
        assertThat(contar("auth_permission")).isEqualTo(permisosAntes);
        assertThat(contar("auth_role_permission")).isEqualTo(concesionesAntes);
        assertThat(permisosDelRolEn("admin", "admin_user")).containsExactly("apps:leer");
        assertThat(permisosDelRolEn("admin", "admin")).containsExactly("*:*");
    }

    @Autowired
    private DataSource fuente;

    private List<String> permisosDelRolEn(String app, String rol) {
        return jdbc.sql("""
                        SELECT p.resource, p.verb FROM auth_permission p
                          JOIN auth_role_permission rp ON rp.permission_id = p.id
                          JOIN auth_role r ON r.id = rp.role_id
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = :app AND r.name = :rol
                        """).param("app", app).param("rol", rol)
                .query((rs, n) -> rs.getString("resource") + ":" + rs.getString("verb")).list();
    }

    @Test
    void el_rol_trafficflow_admin_lleva_comodin_y_su_advertencia_escrita() {
        // El comodín concede los 25 permisos, reenvios:crear incluido. Es una
        // decisión tomada con la consecuencia delante, no el resultado de no
        // decidir, y por eso la advertencia vive en la columna -editable sin
        // migración- y no sólo en un comentario del SQL.
        var rol = jdbc.sql("""
                        SELECT r.description FROM auth_role r
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = 'trafficflow' AND r.name = 'trafficflow_admin'
                        """).query(String.class).single();

        assertThat(rol).contains("reenviar").contains("dos veces se paga dos veces");

        var permisos = jdbc.sql("""
                        SELECT p.resource, p.verb FROM auth_permission p
                          JOIN auth_role_permission rp ON rp.permission_id = p.id
                          JOIN auth_role r ON r.id = rp.role_id
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = 'trafficflow' AND r.name = 'trafficflow_admin'
                        """).query((rs, n) -> rs.getString("resource") + ":" + rs.getString("verb")).list();

        assertThat(permisos).containsExactly("*:*");
    }

    @Test
    void trafficflow_tiene_exactamente_tres_roles_y_el_admin_conserva_su_id() {
        // V9 (difgar, 2026-10-04): admin pasa a trafficflow_admin RENOMBRANDO la fila, no
        // creando otra: los usuarios que ya lo tenian (auth_user_role apunta al id) siguen
        // siendo administradores sin tocarlos.
        var roles = jdbc.sql("""
                        SELECT r.id, r.name FROM auth_role r JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = 'trafficflow'
                        """).query((rs, n) -> rs.getString("name") + "=" + rs.getString("id")).list();

        assertThat(roles).hasSize(3).contains("trafficflow_admin=c0000000-0000-4000-8000-000000000006");
        assertThat(roles).anyMatch(r -> r.startsWith("trafficflow_user="))
                .anyMatch(r -> r.startsWith("trafficflow_viewer="));
    }

    @Test
    void trafficflow_user_puede_todo_menos_lo_que_envia_postbacks() {
        // Sin comodin, porque el comodin no admite exclusiones (ver V6): la lista es el
        // catalogo MENOS reenvios:crear y barridos:crear, que son las dos acciones que hacen
        // salir un postback hacia la red (y el pago es nuestro). postbacks:leer si va.
        var permisos = permisosDelRol("trafficflow_user");

        assertThat(permisos).doesNotContain("reenvios:crear", "barridos:crear", "*:*")
                .contains("postbacks:leer", "redes:crear", "campanas:editar", "endpoints:editar",
                        "reglas:borrar", "enlaces:borrar")
                .hasSize(24);
    }

    @Test
    void trafficflow_viewer_solo_lee() {
        assertThat(permisosDelRol("trafficflow_viewer")).containsExactly("*:leer");
    }

    private java.util.List<String> permisosDelRol(String rol) {
        return jdbc.sql("""
                        SELECT p.resource, p.verb FROM auth_permission p
                          JOIN auth_role_permission rp ON rp.permission_id = p.id
                          JOIN auth_role r ON r.id = rp.role_id
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE a.name = 'trafficflow' AND r.name = :rol
                        """).param("rol", rol)
                .query((rs, n) -> rs.getString("resource") + ":" + rs.getString("verb")).list();
    }

    @Test
    void trafficflow_queda_dado_de_alta_con_sus_cuatro_valores() {
        var trafficflow = configuracionCliente("trafficflow");

        assertThat(trafficflow.redirectUris()).isEqualTo(
                "https://traffic.mobile-americas.com/callback,http://localhost:5174/callback");
        assertThat(trafficflow.postLogoutRedirectUris()).isEqualTo(
                "https://traffic.mobile-americas.com/,http://localhost:5174/");
        assertThat(trafficflow.accessTtlSeconds()).isEqualTo(7200L);
    }

    @Test
    void el_enlace_de_trafficflow_en_el_menu_lleva_al_panel_y_no_a_los_clics() {
        // tf.mobile-americas.com son ahora los CLICS (MS-1); el panel vive en traffic. Esta
        // url es la que pinta el menu del admin (claim `apps`): con tf. llevaria al redirect
        // de clics, no al panel.
        var url = jdbc.sql("SELECT url FROM auth_app WHERE name = 'trafficflow'")
                .query(String.class).single();

        assertThat(url).isEqualTo("https://traffic.mobile-americas.com");
    }

    @Test
    void el_catalogo_de_trafficflow_tiene_exactamente_los_veintiseis_permisos() {
        // containsExactlyInAnyOrder, no contains: un permiso de más -por
        // ejemplo, un 'postbacks:reenviar' colado por error- es una concesión
        // que nadie pidió y debe hacer fallar esta prueba tanto como uno de menos.
        // resource <> '*' porque el comodín NO es una entrada del catálogo: es
        // la forma de una concesión. Es la misma condición que aplica
        // JpaAppRepository.findResourcesByAppId, que es quien lo expande, y
        // por eso V6 puede añadir el '*:*' del rol admin sin que esta lista
        // de 25 cambie. Sin ese filtro, el test contaría concesiones y no
        // recursos, y fallaría cada vez que se cree un rol con comodín.
        var permisos = jdbc.sql("""
                        SELECT p.resource, p.verb FROM auth_permission p
                          JOIN auth_app a ON a.id = p.app_id
                         WHERE a.name = 'trafficflow' AND p.resource <> '*'
                        """)
                .query((rs, n) -> rs.getString("resource") + ":" + rs.getString("verb"))
                .list();

        assertThat(permisos).containsExactlyInAnyOrder(
                "redes:crear", "redes:leer", "redes:editar",
                "servicios:crear", "servicios:leer", "servicios:editar",
                "campanas:crear", "campanas:leer", "campanas:editar",
                "enlaces:crear", "enlaces:leer", "enlaces:borrar",
                "reglas:crear", "reglas:leer", "reglas:editar", "reglas:borrar",
                "endpoints:crear", "endpoints:leer", "endpoints:editar",
                "postbacks:leer",
                "reenvios:crear",
                // V8: el barrido a demanda de postbacks (POST /postbacks/barrido) crea un
                // barrido. Recurso propio y verbo 'crear', como reenvios:crear, porque el
                // verbo es un enum cerrado.
                "barridos:crear",
                "informe:leer",
                "auditoria:leer",
                "cache:leer",
                "busqueda:leer");
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
