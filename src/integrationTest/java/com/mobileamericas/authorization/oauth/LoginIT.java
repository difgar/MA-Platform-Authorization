package com.mobileamericas.authorization.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * El login federado con Google y la sesión SSO que deja persistida.
 *
 * Corre contra los dos motores (ver las subclases) y no por simetría con el
 * resto de la suite: la sesión se guarda en SPRING_SESSION_ATTRIBUTES, la única
 * tabla del proyecto con una migración por motor (ATTRIBUTE_BYTES es BLOB en
 * MySQL y BYTEA en PostgreSQL). Que este flujo se ejecute entero en ambos es
 * exactamente lo que justifica esa excepción.
 */
public abstract class LoginIT extends BaseOauthIT {

    /** Las columnas son las que siembra V2__datos_iniciales.sql. */
    private static final String SQL_INSERTAR_INACTIVO = """
            INSERT INTO auth_user (id, email, full_name, active, created_at, updated_at)
            VALUES (:id, :email, NULL, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """;

    @Test
    void un_usuario_conocido_inicia_sesion_y_la_sesion_se_persiste() {
        var sesionesAntes = contar("SPRING_SESSION");

        var cookie = iniciarSesionCon("usuario1@pendiente.local");

        assertThat(cookie).isNotEmpty();
        assertThat(contar("SPRING_SESSION")).isGreaterThan(sesionesAntes);

        // Que la tabla crezca no basta y no discrimina: el paso 1 del login ya
        // crea una sesión para guardar la petición de autorización, así que
        // SPRING_SESSION crece igual cuando el login FRACASA. Lo que demuestra
        // que la sesión es la de un usuario autenticado es su PRINCIPAL_NAME.
        assertThat(principalesEnSesion()).contains("usuario1@pendiente.local");

        // Y el contexto de seguridad serializado, que es lo que de verdad
        // viaja por la columna binaria con un tipo distinto en cada motor.
        assertThat(atributosDeLaSesionDe("usuario1@pendiente.local"))
                .contains("SPRING_SECURITY_CONTEXT");
    }

    /**
     * El identificador de la sesión es el email en minúsculas, no el que haya
     * mandado el proveedor: es la clave con la que /oauth2/authorize buscará
     * los roles del usuario, y la fase 1 arrastró un fallo justo aquí -la
     * identidad resultaba dependiente de la colación del motor, el mismo email
     * encontraba usuario en MySQL y no en PostgreSQL-.
     *
     * Las dos aserciones comparan en Java, no en SQL, a propósito: un
     * 'WHERE principal_name = ...' no distingue mayúsculas en MySQL
     * (utf8mb4_0900_ai_ci) y daría por bueno el email sin normalizar.
     */
    @Test
    void el_email_del_proveedor_se_normaliza_antes_de_entrar_en_la_sesion() {
        // Antes/después, y no un contains suelto: la prueba de más arriba deja
        // una sesión de usuario1 en la misma base de datos, así que un
        // contains("usuario1@pendiente.local") pasaría por SU sesión y sólo
        // discriminaría la mitad doesNotContain.
        var normalizadasAntes = sesionesDe("usuario1@pendiente.local");

        iniciarSesionCon("USUARIO1@Pendiente.Local");

        assertThat(sesionesDe("usuario1@pendiente.local")).isEqualTo(normalizadasAntes + 1);
        assertThat(principalesEnSesion()).doesNotContain("USUARIO1@Pendiente.Local");
    }

    /**
     * El «Produces» de esta tarea: /oauth2/authorize alcanzable CON sesión.
     *
     * Cierra tres huecos de una vez, y por eso vale más que su tamaño: es lo
     * único que usa la cookie que devuelve iniciarSesionCon, lo único que
     * ejecuta pedirAutorizacion y redirectUriDe antes de entregarlos a las
     * tareas 7 y 8, y lo único que RELEE el SPRING_SECURITY_CONTEXT
     * serializado -la mitad de la excepción de migración por motor que hasta
     * ahora sólo se escribía-.
     *
     * Con la sesión viva no hay pantalla de consentimiento (el registro pone
     * requireAuthorizationConsent(false)), así que la respuesta es
     * directamente la vuelta al cliente con el código.
     */
    @Test
    void con_sesion_authorize_emite_un_codigo() {
        var cookie = iniciarSesionCon("usuario1@pendiente.local");

        var r = pedirAutorizacion(cookie, "admin");

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(r.getHeaders().getLocation()).isNotNull();
        assertThat(r.getHeaders().getLocation().toString())
                .as("sin sesión esto sería la redirección al login, no la vuelta al cliente")
                .startsWith("https://admin.mobile-americas.com/callback")
                .contains("code=");
    }

    /**
     * El flujo del navegador entero, que es el que de verdad recorre un
     * usuario: pide autorización sin sesión, acaba en Google y vuelve a la
     * petición que había quedado guardada.
     *
     * Verifica la decisión del request cache acotado (ver SecurityConfig):
     * quien GUARDA la petición es la cadena @Order(1) y quien la RECUPERA es
     * el manejador de éxito de oauth2Login, que vive en la @Order(2) y tiene
     * un cache que no guarda nada. Que el paso 3 devuelva a /oauth2/authorize
     * y no a la raíz es lo que demuestra que acotar el guardado no rompe la
     * recuperación; si lo rompiera, el usuario acabaría en una página que no
     * existe y el código nunca se emitiría.
     */
    @Test
    void sin_sesion_authorize_manda_al_login_y_al_volver_emite_el_codigo() {
        // 1. Navegador sin sesión: al login. Aquí SÍ se estrena sesión, y hace
        //    falta: es donde queda guardada su petición.
        var alLogin = get(urlDeAutorizacion("admin", RETO_POR_DEFECTO), null);
        assertThat(alLogin.statusCode()).isEqualTo(302);
        assertThat(alLogin.headers().firstValue("Location").orElseThrow())
                .endsWith("/oauth2/authorization/google");
        var cookie = aplicarCookies("", alLogin);
        assertThat(cookie).as("sin sesión no hay dónde guardar la petición").isNotEmpty();

        // 2. El login, siguiendo esa redirección con la misma cookie.
        var aGoogle = get(urlBase() + "/oauth2/authorization/google", cookie);
        cookie = aplicarCookies(cookie, aGoogle);
        var vuelta = GoogleSimulado.arrancar().callbackPara(
                aGoogle.headers().firstValue("Location").orElseThrow(),
                "usuario1@pendiente.local", true);
        var callback = get(vuelta, cookie);
        cookie = aplicarCookies(cookie, callback);

        // 3. El manejador de éxito devuelve a la petición guardada, no a "/".
        var vueltaAlAuthorize = callback.headers().firstValue("Location").orElseThrow();
        assertThat(vueltaAlAuthorize)
                .as("si la petición guardada se hubiera perdido, esto sería la raíz")
                .contains("/oauth2/authorize");

        // 4. Y ahí, ya con sesión, sale el código.
        var conCodigo = get(vueltaAlAuthorize, cookie);
        assertThat(conCodigo.statusCode()).isEqualTo(302);
        assertThat(conCodigo.headers().firstValue("Location").orElseThrow())
                .startsWith("https://admin.mobile-americas.com/callback")
                .contains("code=");
    }

    /**
     * ExceptionTranslationFilter guarda la petición rechazada ANTES de invocar
     * el entry point, y guardarla crea sesión. Desde que la sesión se
     * persiste, eso convertía cualquier GET anónimo en una fila de
     * SPRING_SESSION con 12 h de vida: consumo de recursos sin autenticar
     * contra la base de datos compartida de la plataforma. Lo acota el
     * requestCache de la cadena de cierre (ver SecurityConfig).
     *
     * La aserción que manda es la de la cookie, y es determinista: si se
     * hubiera creado sesión, el contenedor la anuncia en la respuesta -no
     * puede no hacerlo, o el cliente no podría volver con ella-, mientras que
     * la fila se escribe al terminar la petición y leer la tabla demasiado
     * pronto podría dar un falso verde.
     */
    @Test
    void una_peticion_anonima_no_escribe_sesion_en_la_base_de_datos() {
        var sesionesAntes = contar("SPRING_SESSION");

        var r = get(urlBase() + "/v1/lo-que-sea", null);

        assertThat(r.statusCode())
                .as("la ruta sigue estando denegada: si no, esto no probaría nada")
                .isEqualTo(302);
        assertThat(r.headers().allValues("set-cookie"))
                .as("una petición anónima no debe estrenar sesión")
                .isEmpty();
        assertThat(contar("SPRING_SESSION")).isEqualTo(sesionesAntes);
    }

    @Test
    void un_usuario_que_no_esta_en_auth_user_es_rechazado() {
        var sesionesSuyasAntes = sesionesDe("nadie@ejemplo.com");

        assertThatThrownBy(() -> iniciarSesionCon("nadie@ejemplo.com"))
                .hasMessageContaining("no está dado de alta");

        // Rechazado EN EL LOGIN, que es lo que esta prueba vigila: el
        // desconocido no llega a tener sesión SSO en este servicio. Sin esta
        // aserción, la prueba pasaría igual si el rechazo ocurriera más tarde,
        // en /oauth2/authorize (que es la tarea 7), con el desconocido ya
        // autenticado aquí.
        assertThat(sesionesDe("nadie@ejemplo.com")).isEqualTo(sesionesSuyasAntes);
    }

    /**
     * usuario2 está dado de alta: si esta prueba pasara por "desconocido" en
     * vez de por "email sin verificar" estaría comprobando la otra regla. El
     * mensaje es lo que las distingue.
     */
    @Test
    void un_email_sin_verificar_es_rechazado() {
        var sesionesSuyasAntes = sesionesDe("usuario2@pendiente.local");

        assertThatThrownBy(() -> iniciarSesionConEmailSinVerificar("usuario2@pendiente.local"))
                .hasMessageContaining("verificad");

        assertThat(sesionesDe("usuario2@pendiente.local")).isEqualTo(sesionesSuyasAntes);
    }

    /**
     * Sin email no hay identidad que buscar, y el diagnóstico no debe decir
     * "no verificado", que describe otra cosa: la cuenta puede tener el email
     * perfectamente verificado y simplemente no habérnoslo dado (un scope
     * recortado, una cuenta sin email).
     */
    @Test
    void una_cuenta_sin_email_es_rechazada_por_no_traer_email() {
        assertThatThrownBy(() -> iniciarSesionCon(""))
                .hasMessageContaining("email_ausente")
                .hasMessageContaining("ningún email")
                .hasMessageNotContaining("email_no_verificado");
    }

    /**
     * Estar dado de baja y no existir son cosas distintas, y las dos se
     * rechazan en el login. Fila propia y no un UPDATE sobre usuario1 o
     * usuario2: así la prueba no depende del orden de ejecución ni le cambia
     * el escenario a ninguna otra de esta clase.
     */
    @Test
    void un_usuario_dado_de_baja_es_rechazado() {
        insertarUsuarioInactivo("inactivo@pendiente.local");
        var sesionesSuyasAntes = sesionesDe("inactivo@pendiente.local");

        assertThatThrownBy(() -> iniciarSesionCon("inactivo@pendiente.local"))
                .hasMessageContaining("dado de baja")
                // Y no por el otro motivo: la fila existe, así que un rechazo
                // por 'usuario_desconocido' sería un diagnóstico falso.
                .hasMessageContaining("usuario_inactivo");

        assertThat(sesionesDe("inactivo@pendiente.local")).isEqualTo(sesionesSuyasAntes);
    }

    private void insertarUsuarioInactivo(String email) {
        jdbc.sql(SQL_INSERTAR_INACTIVO)
                .param("id", UUID.randomUUID().toString())
                .param("email", email)
                .update();
    }

    private long contar(String tabla) {
        return jdbc.sql("SELECT count(*) FROM " + tabla).query(Long.class).single();
    }

    private List<String> principalesEnSesion() {
        return jdbc.sql("SELECT PRINCIPAL_NAME FROM SPRING_SESSION WHERE PRINCIPAL_NAME IS NOT NULL")
                .query(String.class).list();
    }

    /** Se filtra en Java, no en SQL: ver el comentario de la prueba de normalización. */
    private long sesionesDe(String principal) {
        return principalesEnSesion().stream().filter(principal::equals).count();
    }

    private List<String> atributosDeLaSesionDe(String principal) {
        return jdbc.sql("""
                        SELECT a.ATTRIBUTE_NAME
                          FROM SPRING_SESSION_ATTRIBUTES a
                          JOIN SPRING_SESSION s ON s.PRIMARY_ID = a.SESSION_PRIMARY_ID
                         WHERE s.PRINCIPAL_NAME = :principal
                        """)
                .param("principal", principal)
                .query(String.class).list();
    }
}
