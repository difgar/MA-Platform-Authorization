package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ToolchainTest {

    @Test
    void corre_sobre_java_25_o_superior() {
        assertThat(Runtime.version().feature()).isGreaterThanOrEqualTo(25);
    }

    @Test
    void los_records_del_dominio_son_utilizables() {
        record Prueba(String valor) {}
        assertThat(new Prueba("x").valor()).isEqualTo("x");
    }
}
