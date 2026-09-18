package com.mobileamericas.authorization.domain;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AccessGrantTest {

    private static final UUID APP_ID = UUID.randomUUID();
    private static final App APP =
            new App(APP_ID, "trafficflow", "https://tf.example", true);
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
        // Esta rama es hoy lo ÚNICO que para una app desactivada. La fase 1
        // tenía además un rechazo aguas arriba, en el verificador de Google,
        // pero solo corría en el login inicial y ya no existe: la fase 2
        // retiró la emisión propia. Con el modelo nuevo el desfase es mayor,
        // no menor -quien pide un token trae una sesión establecida hace rato
        // y nadie vuelve a mirar si su app sigue activa-, así que la
        // comprobación tiene que vivir aquí, en el dominio, donde se construye
        // cada grant.
        var appDesactivada = new App(APP_ID, "trafficflow", "https://tf.example", false);
        var usuario = usuarioCon(Set.of(Permission.parse("*:*")));

        assertThat(AccessGrant.of(usuario, appDesactivada, CATALOGO).isEmpty()).isTrue();
    }
}
