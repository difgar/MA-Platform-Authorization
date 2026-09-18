package com.mobileamericas.authorization.oauth;

import org.junit.jupiter.api.Test;

import java.util.List;

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
        iniciarSesionCon("USUARIO1@Pendiente.Local");

        assertThat(principalesEnSesion())
                .contains("usuario1@pendiente.local")
                .doesNotContain("USUARIO1@Pendiente.Local");
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
