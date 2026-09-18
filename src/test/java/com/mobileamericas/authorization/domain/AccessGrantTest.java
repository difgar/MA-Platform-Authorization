package com.mobileamericas.authorization.domain;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AccessGrantTest {

    private static final UUID APP_ID = UUID.randomUUID();
    // redirectUris/postLogoutRedirectUris/accessTtlSeconds son irrelevantes
    // aquí: esta clase prueba la expansión de permisos, no el registro OAuth.
    private static final App APP =
            new App(APP_ID, "trafficflow", "https://tf.example", true, List.of(), List.of(), null);
    private static final Set<String> CATALOGO = Set.of("campanas", "redes");

    private static User usuarioCon(Set<Permission> permisos) {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, permisos);
        return new User(UUID.randomUUID(), "p@ejemplo.com", "Persona", true, Set.of(rol));
    }

    @Test
    void expande_el_comodin_total_a_todos_los_recursos_por_todos_los_verbos() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:*"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactlyInAnyOrder(
                "campanas:crear", "campanas:leer", "campanas:editar", "campanas:borrar",
                "redes:crear", "redes:leer", "redes:editar", "redes:borrar");
    }

    @Test
    void expande_un_comodin_de_recurso_conservando_el_verbo() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:leer"))), APP, CATALOGO);

        assertThat(grant.authorities())
                .containsExactlyInAnyOrder("campanas:leer", "redes:leer");
    }

    @Test
    void expande_un_comodin_de_verbo_conservando_el_recurso() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("campanas:*"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactlyInAnyOrder(
                "campanas:crear", "campanas:leer", "campanas:editar", "campanas:borrar");
    }

    @Test
    void deja_intacto_un_permiso_concreto() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("redes:editar"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactly("redes:editar");
    }

    @Test
    void ignora_los_roles_de_otras_aplicaciones() {
        var rolDeOtraApp = new Role(
                UUID.randomUUID(), "admin", UUID.randomUUID(), Set.of(Permission.parse("*:*")));
        var rolDeEsta = new Role(
                UUID.randomUUID(), "operador", APP_ID, Set.of(Permission.parse("redes:leer")));
        var usuario = new User(
                UUID.randomUUID(), "p@ejemplo.com", "Persona", true, Set.of(rolDeOtraApp, rolDeEsta));

        var grant = AccessGrant.of(usuario, APP, CATALOGO);

        assertThat(grant.authorities()).containsExactly("redes:leer");
        assertThat(grant.roleNames()).containsExactly("operador");
    }

    @Test
    void un_comodin_sobre_un_catalogo_vacio_no_concede_nada() {
        // El hueco que detectó la revisión del diseño: una app que solo declara
        // comodines dejaría a su administrador sin autoridades, en silencio.
        // Aquí se hace visible; la validación al alta vive en la tarea 4.
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:*"))), APP, Set.of());

        assertThat(grant.authorities()).isEmpty();
        assertThat(grant.isEmpty()).isTrue();
    }

    @Test
    void un_usuario_inactivo_no_concede_nada() {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, Set.of(Permission.parse("*:*")));
        var inactivo = new User(UUID.randomUUID(), "p@ejemplo.com", "Persona", false, Set.of(rol));

        assertThat(AccessGrant.of(inactivo, APP, CATALOGO).isEmpty()).isTrue();
    }

    @Test
    void una_app_desactivada_no_concede_nada() {
        // Esta rama NO es el único freno a una app desactivada, aunque este
        // comentario lo dijera: desde la tarea 4,
        // RegisteredClientRepositoryAdapter devuelve null para una app con
        // active = FALSE (RegistroDeClientesIT.una_app_desactivada_no_se_ofrece_como_cliente),
        // y para el framework un cliente nulo es un cliente desconocido, así
        // que /oauth2/authorize corta antes con 'invalid_client'.
        //
        // Sigue haciendo falta igual, y por lo mismo que entonces: es la última
        // barrera, la que se aplica en cada construcción de grant y no sólo al
        // pedir el código. La fase 1 tenía además un rechazo aguas arriba en el
        // verificador de Google, que ya no existe -la fase 2 retiró la emisión
        // propia-, y con el modelo nuevo el desfase entre el login y la emisión
        // es mayor, no menor: quien pide un token trae una sesión establecida
        // hace rato. Por eso la comprobación vive aquí, en el dominio.
        var appDesactivada = new App(APP_ID, "trafficflow", "https://tf.example", false, List.of(), List.of(), null);
        var usuario = usuarioCon(Set.of(Permission.parse("*:*")));

        assertThat(AccessGrant.of(usuario, appDesactivada, CATALOGO).isEmpty()).isTrue();
    }
}
