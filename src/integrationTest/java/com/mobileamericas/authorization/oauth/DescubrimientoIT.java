package com.mobileamericas.authorization.oauth;

import com.mobileamericas.authorization.BaseIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * El authorization server publica su documento de descubrimiento sin
 * autenticación. Es la prueba mínima de que el framework está activo.
 *
 * {@code @AutoConfigureTestRestTemplate} por el mismo motivo que en el resto
 * de la suite: en Boot 4, TestRestTemplate ya no se autoconfigura solo por
 * usar webEnvironment = RANDOM_PORT y vive en otro paquete
 * (org.springframework.boot.resttestclient).
 */
@AutoConfigureTestRestTemplate
public abstract class DescubrimientoIT extends BaseIT {

    @Autowired TestRestTemplate http;

    @Test
    void publica_el_documento_de_descubrimiento() {
        var r = http.getForObject("/.well-known/openid-configuration", String.class);

        assertThat(r)
                .contains("\"authorization_endpoint\"")
                .contains("\"token_endpoint\"")
                .contains("\"jwks_uri\"")
                .contains("\"end_session_endpoint\"");
    }

    @Test
    void el_jwks_sigue_sirviendo_solo_material_publico() {
        var r = http.getForObject("/oauth2/jwks", String.class);

        assertThat(r).contains("\"n\"").contains("\"e\"");
        assertThat(r).doesNotContain("\"d\"").doesNotContain("\"p\"").doesNotContain("\"q\"");
    }
}
