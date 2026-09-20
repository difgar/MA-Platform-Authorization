package com.mobileamericas.authorization.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * El validador de {@code /authorize}: un usuario sin ningún rol en la app que
 * pide el token no debe recibirlo. Sin este validador, AccessGrant devolvería
 * un grant vacío y el framework emitiría igualmente un código -y luego un
 * token con cero autoridades-, que es peor que un rechazo: la aplicación cree
 * que el usuario ha entrado y no puede hacer nada, sin que nadie sepa por qué.
 * El mismo fallo silencioso que la fase 1 corrigió en grantDe.
 */
public abstract class AccesoAlClienteIT extends BaseOauthIT {

    /**
     * V2__datos_iniciales.sql da de alta a usuario2 con analyst@admin Y CON
     * admin@fgf (ver el comentario de esa migración): para probar "ningún rol
     * en la app" hay que retirar esa segunda asignación primero, la del seed
     * no sirve tal cual para este escenario. Se hace con un DELETE contra
     * nombres (email, nombre de app), no contra los UUID fijos de la
     * migración, para no depender de que no cambien.
     *
     * El contenedor de base de datos es propio de esta clase de prueba (ver
     * las subclases): mutar esta fila no afecta a LoginIT, RegistroDeClientesIT
     * ni a ninguna otra suite, que corren cada una contra su propio contenedor.
     */
    private void retirarRolDeUsuario2EnFgf() {
        jdbc.sql("""
                        DELETE FROM auth_user_role
                         WHERE user_id = (SELECT id FROM auth_user WHERE email = :email)
                           AND role_id IN (
                               SELECT id FROM auth_role
                                WHERE app_id = (SELECT id FROM auth_app WHERE name = :app))
                        """)
                .param("email", "usuario2@pendiente.local")
                .param("app", "fgf")
                .update();
    }

    /**
     * ⚠️ Esta prueba afirma la REDIRECCIÓN al cliente, no sólo la ausencia de
     * código: con la excepción del validador mal construida (segundo
     * argumento null en vez de ctx.getAuthentication()) el usuario recibe un
     * 400 crudo en la pantalla de auth en lugar de volver a su aplicación, y
     * un assert que sólo mirara "no hay code=" pasaría igual con ese 400.
     */
    @Test
    void sin_roles_en_la_app_devuelve_access_denied_al_cliente() {
        retirarRolDeUsuario2EnFgf();
        var cookie = iniciarSesionCon("usuario2@pendiente.local");

        var r = pedirAutorizacion(cookie, "fgf");

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString())
                .startsWith("https://fgf.mobile-americas.com/callback")
                .contains("error=access_denied");
    }

    /** usuario2 sí tiene analyst@admin (de fábrica, sin tocar el seed): con roles, código. */
    @Test
    void con_roles_en_la_app_devuelve_un_codigo() {
        var cookie = iniciarSesionCon("usuario2@pendiente.local");

        var r = pedirAutorizacion(cookie, "admin");

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString())
                .contains("code=")
                .doesNotContain("error=");
    }

    /**
     * Fila propia con su propio email, igual que
     * LoginIT.insertarUsuarioInactivo: así ninguno de los dos tests de abajo
     * -uno desactiva, el otro borra- pisa al otro ni depende del orden en que
     * JUnit los ejecute. El rol es admin@admin (comodín *:*), para que
     * AccessGrant.of tenga algo que conceder si no fuera por la baja o el
     * borrado: sin un rol real, el rechazo no probaría lo que dice probar.
     */
    private void insertarUsuarioConRolAdminEnAdmin(String email) {
        var id = UUID.randomUUID().toString();
        jdbc.sql("""
                        INSERT INTO auth_user (id, email, full_name, active, created_at, updated_at)
                        VALUES (:id, :email, NULL, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """)
                .param("id", id)
                .param("email", email)
                .update();
        jdbc.sql("""
                        INSERT INTO auth_user_role (user_id, role_id)
                        VALUES (:userId, 'c0000000-0000-4000-8000-000000000001')
                        """)
                .param("userId", id)
                .update();
    }

    /**
     * Dado de baja DESPUÉS de iniciar sesión, no antes: la tarea 5 sólo
     * rechaza en el LOGIN, así que una sesión ya establecida sigue viva tras
     * el UPDATE. Es justo el camino que AccessGrant.of ya cubre -un usuario
     * inactivo concede un grant vacío, active() se mira antes que los roles-,
     * y este validador delega en él sin más: la misma excepción
     * access_denied que "sin roles", no un token con autoridades para
     * alguien dado de baja.
     */
    @Test
    void un_usuario_dado_de_baja_con_sesion_viva_devuelve_access_denied() {
        insertarUsuarioConRolAdminEnAdmin("baja@pendiente.local");
        var cookie = iniciarSesionCon("baja@pendiente.local");
        jdbc.sql("UPDATE auth_user SET active = FALSE WHERE email = :email")
                .param("email", "baja@pendiente.local")
                .update();

        var r = pedirAutorizacion(cookie, "admin");

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString())
                .startsWith("https://admin.mobile-americas.com/callback")
                .contains("error=access_denied");
    }

    /**
     * El hallazgo de la ronda 1: el .orElseThrow() literal del brief
     * convertía un Optional vacío en un 500 crudo -la pantalla que esta tarea
     * existe para no ensuciar-, alcanzable en producción con un usuario
     * BORRADO (no sólo desactivado) mientras su sesión sigue viva. Se borra
     * la fila entera -primero sus roles, por la FK-, no un UPDATE: eso es lo
     * que deja a usuarios.findByEmail(...) devolviendo Optional.empty(), la
     * rama que trata la ausencia como el mismo access_denied que la falta de
     * roles, no como un error de servidor.
     */
    @Test
    void un_usuario_borrado_con_sesion_viva_devuelve_access_denied_no_500() {
        insertarUsuarioConRolAdminEnAdmin("borrado@pendiente.local");
        var cookie = iniciarSesionCon("borrado@pendiente.local");
        jdbc.sql("DELETE FROM auth_user_role WHERE user_id = "
                        + "(SELECT id FROM auth_user WHERE email = :email)")
                .param("email", "borrado@pendiente.local")
                .update();
        jdbc.sql("DELETE FROM auth_user WHERE email = :email")
                .param("email", "borrado@pendiente.local")
                .update();

        var r = pedirAutorizacion(cookie, "admin");

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString())
                .startsWith("https://admin.mobile-americas.com/callback")
                .contains("error=access_denied");
    }

    /**
     * El motivo viaja ESCRITO, no por la ausencia de uno.
     *
     * Antes, un consumidor sólo podía reconocer este rechazo porque no traía
     * 'error_reason' — o sea, un significado que viajaba en un hueco. Y un
     * hueco lo produce cualquiera: la integración de TrafficFlow encontró que
     * una caída de red o una respuesta a medias tampoco traen motivo, así que
     * la pantalla común le decía «tu cuenta no tiene permiso» a alguien cuyo
     * problema era internet. Con el motivo escrito, la ausencia deja de decir
     * nada y cae al mensaje genérico, que es lo correcto para «no sé qué pasó».
     */
    @Test
    void el_rechazo_dice_su_motivo_en_vez_de_dejarlo_en_el_hueco() {
        var cookie = iniciarSesionCon("usuario2@pendiente.local");

        var r = pedirAutorizacion(cookie, "fgf");

        assertThat(r.getHeaders().getLocation().toString())
                .contains("error=access_denied")
                .contains("error_reason=sin_rol");
    }
}
