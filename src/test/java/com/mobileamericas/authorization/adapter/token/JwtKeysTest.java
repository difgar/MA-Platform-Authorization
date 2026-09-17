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
        // Vía fromJson(): prueba la rama 'kid == null'.
        var sinKid = new RSAKeyGenerator(2048).generate();

        assertThatThrownBy(() -> JwtKeys.fromJson(List.of(sinKid.toJSONString())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kid");
    }

    @Test
    void rechaza_una_clave_con_kid_en_blanco() throws Exception {
        // La otra rama de la misma condición: un 'kid' que no es null pero
        // tampoco sirve para nada. Vía forTesting(), para probar que la
        // invariante vive en el constructor y no solo en el camino de parse().
        var kidEnBlanco = new RSAKeyGenerator(2048).keyID("   ").generate();

        assertThatThrownBy(() -> JwtKeys.forTesting(kidEnBlanco))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kid");
    }

    @Test
    void rechaza_una_clave_sin_parte_privada() throws Exception {
        // También vía forTesting(): la clave activa firma tokens, así que una
        // clave solo-pública no sirve, venga de donde venga.
        var soloPublica = new RSAKeyGenerator(2048).keyID("pub-only").generate().toPublicJWK();

        assertThatThrownBy(() -> JwtKeys.forTesting(soloPublica))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("parte privada");
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
