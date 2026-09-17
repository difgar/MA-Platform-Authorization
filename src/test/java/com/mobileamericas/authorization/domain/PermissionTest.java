package com.mobileamericas.authorization.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionTest {

    @Test
    void parsea_recurso_y_verbo() {
        var p = Permission.parse("campanas:editar");
        assertThat(p.resource()).isEqualTo("campanas");
        assertThat(p.verb()).isEqualTo("editar");
    }

    @Test
    void reconoce_los_comodines() {
        assertThat(Permission.parse("*:*").isWildcard()).isTrue();
        assertThat(Permission.parse("*:leer").isWildcard()).isTrue();
        assertThat(Permission.parse("campanas:*").isWildcard()).isTrue();
        assertThat(Permission.parse("campanas:leer").isWildcard()).isFalse();
    }

    @Test
    void rechaza_un_verbo_que_no_existe() {
        // 'escribir' fue descartado a propósito: agrupaba crear, editar y borrar,
        // y habría concedido borrado a roles que hoy no lo tienen.
        assertThatThrownBy(() -> Permission.parse("campanas:escribir"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("escribir");
    }

    @Test
    void rechaza_una_cadena_sin_dos_puntos() {
        assertThatThrownBy(() -> Permission.parse("campanas"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void se_serializa_como_autoridad() {
        assertThat(Permission.parse("redes:borrar").asAuthority()).isEqualTo("redes:borrar");
    }
}
