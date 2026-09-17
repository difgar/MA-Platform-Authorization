package com.mobileamericas.authorization.config;

import com.mobileamericas.authorization.adapter.token.JwtKeys;
import com.mobileamericas.authorization.adapter.token.JwtProperties;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * selfJwtDecoder añade una comprobación de PRESENCIA de 'aud' que
 * JwtValidators.createDefaultWithIssuer() no hace (ver el comentario de
 * BeansConfig). No es una restricción de valor -eso es una decisión de fase 2,
 * ver README.md- solo de que el claim exista y no venga vacío.
 */
class BeansConfigTest {

    private static final String EMISOR = "https://auth.mobile-americas.com";

    private RSAKey clave;
    private JwtDecoder decoder;

    @BeforeEach
    void preparar() throws Exception {
        clave = new RSAKeyGenerator(2048).keyID("self-2026-09").generate();
        var keys = JwtKeys.forTesting(clave);
        var props = new JwtProperties(
                EMISOR, Duration.ofMinutes(15), Duration.ofHours(12), List.of("classpath:no-se-usa.jwk"));
        decoder = new BeansConfig().selfJwtDecoder(keys, props);
    }

    private String tokenConAudiencia(List<String> aud) {
        var encoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
                new com.nimbusds.jose.jwk.JWKSet(clave)));
        var builder = JwtClaimsSet.builder()
                .issuer(EMISOR)
                .subject("d0000000-0000-4000-8000-000000000001")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES));
        if (aud != null && !aud.isEmpty()) {
            builder.audience(aud);
        }
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(clave.getKeyID()).build();
        return encoder.encode(JwtEncoderParameters.from(header, builder.build())).getTokenValue();
    }

    @Test
    void acepta_un_token_con_audiencia() {
        var jwt = decoder.decode(tokenConAudiencia(List.of("admin")));

        assertThat(jwt.getAudience()).containsExactly("admin");
    }

    @Test
    void rechaza_un_token_sin_audiencia() {
        var sinAud = tokenConAudiencia(null);

        assertThatThrownBy(() -> decoder.decode(sinAud))
                .isInstanceOf(JwtValidationException.class);
    }
}
