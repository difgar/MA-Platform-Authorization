package com.mobileamericas.authorization.adapter.token;

import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtKeysTest {

    @Test
    void rechaza_una_clave_sin_kid() throws Exception {
        // Sin 'kid' no hay forma de firmar con una clave concreta de la lista
        // ni de que un consumidor la seleccione al verificar contra el JWKS.
        var sinKid = new RSAKeyGenerator(2048).generate();

        assertThatThrownBy(() -> JwtKeys.fromJson(List.of(sinKid.toJSONString())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kid");
    }

    @Test
    void rechaza_dos_claves_con_el_mismo_kid() throws Exception {
        // Un kid duplicado hace ambigua la selección: ¿con cuál se firmó, o
        // contra cuál debería verificar un consumidor que lee el JWKS?
        var primera = new RSAKeyGenerator(2048).keyID("dup").generate();
        var segunda = new RSAKeyGenerator(2048).keyID("dup").generate();

        assertThatThrownBy(() -> JwtKeys.fromJson(List.of(primera.toJSONString(), segunda.toJSONString())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("dup");
    }
}
