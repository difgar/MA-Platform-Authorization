package com.mobileamericas.authorization.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

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

        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString()).contains("code=");
    }
}
