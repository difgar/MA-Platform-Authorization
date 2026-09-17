package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.domain.AccessGrant;
import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import tools.jackson.databind.ObjectMapper;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaTokenIssuerTest {

    private static final String EMISOR = "https://auth.mobile-americas.com";
    private static final UUID APP_ID = UUID.randomUUID();

    private RSAKey clave;
    private RSAPublicKey clavePublica;
    private RsaTokenIssuer emisor;
    private JwtDecoder decodificador;

    @BeforeEach
    void preparar() throws Exception {
        // Claves generadas en el test: cero dependencia de Google y del entorno.
        clave = new RSAKeyGenerator(2048).keyID("test-2026-09").generate();
        clavePublica = clave.toRSAPublicKey();
        var keys = JwtKeys.forTesting(clave);
        emisor = new RsaTokenIssuer(keys, new JwtProperties(
                EMISOR, Duration.ofMinutes(15), Duration.ofHours(12), List.of("classpath:no-se-usa.jwk")));
        decodificador = NimbusJwtDecoder.withPublicKey(clavePublica).build();
    }

    private AccessGrant grant() {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID,
                Set.of(Permission.parse("campanas:leer"), Permission.parse("campanas:editar")));
        var usuario = new User(
                UUID.fromString("d0000000-0000-4000-8000-000000000001"),
                "persona@ejemplo.com", "Persona", true, Set.of(rol));
        var app = new App(APP_ID, "trafficflow", "cliente-123", null, true);
        return AccessGrant.of(usuario, app, Set.of("campanas"));
    }

    @Test
    void el_token_se_verifica_con_la_clave_publica() {
        var jwt = decodificador.decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getSubject()).isEqualTo("d0000000-0000-4000-8000-000000000001");
        assertThat(jwt.getIssuer()).hasToString(EMISOR);
        assertThat(jwt.getAudience()).containsExactly("trafficflow");
    }

    @Test
    void el_sub_es_el_uuid_y_no_el_email() {
        // El email puede cambiar; el identificador del sujeto debe ser estable.
        var jwt = decodificador.decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getSubject()).doesNotContain("@");
        assertThat(jwt.getClaimAsString("email")).isEqualTo("persona@ejemplo.com");
    }

    @Test
    void lleva_las_autoridades_ya_expandidas() {
        var jwt = decodificador.decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getClaimAsStringList("permissions"))
                .containsExactlyInAnyOrder("campanas:leer", "campanas:editar")
                .doesNotContain("*:*");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("operador");
    }

    @Test
    void la_cabecera_lleva_el_kid_para_poder_rotar() {
        var jwt = decodificador.decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getHeaders()).containsEntry("kid", "test-2026-09");
        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256");
    }

    @Test
    void un_resource_server_de_otra_app_rechaza_el_token() {
        // El aislamiento entre aplicaciones (§8 del spec). Un token emitido para
        // 'trafficflow' no debe valer contra un servicio configurado para 'admin',
        // y eso lo hace el propio resource server, sin código nuestro.
        var token = emisor.issueAccessToken(grant());

        var comoTrafficflow = NimbusJwtDecoder.withPublicKey(clavePublica).build();
        comoTrafficflow.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), new JwtClaimValidator<List<String>>(
                        "aud", aud -> aud != null && aud.contains("trafficflow"))));
        assertThat(comoTrafficflow.decode(token)).isNotNull();

        var comoAdmin = NimbusJwtDecoder.withPublicKey(clavePublica).build();
        comoAdmin.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), new JwtClaimValidator<List<String>>(
                        "aud", aud -> aud != null && aud.contains("admin"))));

        assertThatThrownBy(() -> comoAdmin.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void caduca_a_los_quince_minutos_y_lleva_jti() {
        var jwt = decodificador.decode(emisor.issueAccessToken(grant()));

        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt()))
                .isEqualTo(Duration.ofMinutes(15));
        assertThat(jwt.getId()).isNotBlank();
    }

    @Test
    void el_jwks_publico_no_contiene_la_clave_privada() {
        // NOTA: publicJwks() devuelve un java.util.Map de verdad (nimbus-jose-jwt
        // 10.x ya no usa net.minidev.json.JSONObject), así que su toString() no es
        // JSON ('{keys=[{kty=RSA, ...}]}', con '=' y sin comillas). Se serializa
        // con el mismo Jackson que expondría el endpoint del JWKS para comprobar
        // el JSON real que vería un consumidor.
        var jwks = new ObjectMapper().writeValueAsString(JwtKeys.forTesting(clave).publicJwks());

        // 'd' es el exponente privado en una JWK RSA; 'p' y 'q' los factores.
        assertThat(jwks).contains("\"n\":").contains("\"e\":").contains("test-2026-09");
        assertThat(jwks).doesNotContain("\"d\":").doesNotContain("\"p\":").doesNotContain("\"q\":");
    }
}
