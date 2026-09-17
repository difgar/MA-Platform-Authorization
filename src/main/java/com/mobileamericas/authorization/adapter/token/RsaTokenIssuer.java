package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.TokenIssuer;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class RsaTokenIssuer implements TokenIssuer {

    private final JwtKeys keys;
    private final JwtProperties props;
    private final JwtEncoder encoder;

    public RsaTokenIssuer(JwtKeys keys, JwtProperties props) {
        this.keys = keys;
        this.props = props;
        this.encoder = new NimbusJwtEncoder(keys.jwkSource());
    }

    @Override
    public String issueAccessToken(AccessGrant grant) {
        var ahora = Instant.now();

        var builder = JwtClaimsSet.builder()
                .issuer(props.issuer())
                // El UUID, no el email: el email puede cambiar y 'sub' debe ser estable.
                .subject(grant.user().id().toString())
                // La app. Aísla 'admin' de 'trafficflow' solo si el consumidor
                // configura spring.security.oauth2.resourceserver.jwt.audiences
                // con su propio nombre; con solo 'jwk-set-uri', Boot no valida
                // 'aud' (ver RsaTokenIssuerTest.un_resource_server_de_otra_app_rechaza_el_token).
                .audience(List.of(grant.app().name()))
                .issuedAt(ahora)
                .expiresAt(ahora.plus(props.accessTtl()))
                .id(UUID.randomUUID().toString())
                .claim("email", grant.user().email())
                .claim("roles", List.copyOf(grant.roleNames()))
                // Autoridades concretas: los comodines ya se expandieron en el dominio.
                .claim("permissions", List.copyOf(grant.authorities()));

        // full_name es NULLABLE en el esquema (V1__esquema.sql): el emisor tiene
        // que tolerar que no haya nombre. JwtClaimsSet.Builder.claim() exige un
        // valor no nulo, así que el claim se omite en vez de mandar null o "":
        // una claim ausente es honesta, mientras que una cadena vacía induciría
        // a un consumidor a creer que el nombre se conoce y está vacío.
        if (grant.user().fullName() != null) {
            builder.claim("name", grant.user().fullName());
        }

        var claims = builder.build();

        var header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keys.activeKeyId())
                .build();

        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    @Override
    public Duration accessTokenTtl() {
        return props.accessTtl();
    }
}
