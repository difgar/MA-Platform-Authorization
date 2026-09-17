package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Component
class RefreshTokenStoreJpa implements RefreshTokenStore {

    private static final SecureRandom ALEATORIO = new SecureRandom();

    private final JpaRefreshTokenRepository jpa;
    private final JwtProperties props;

    RefreshTokenStoreJpa(JpaRefreshTokenRepository jpa, JwtProperties props) {
        this.jpa = jpa;
        this.props = props;
    }

    @Override
    @Transactional
    public IssuedRefreshToken issue(UUID userId, UUID appId) {
        return crear(userId, appId, UUID.randomUUID());
    }

    @Override
    @Transactional
    public IssuedRefreshToken rotate(UUID familyId) {
        // El sujeto se toma de la familia, no de ningún token que llegue de fuera.
        var anterior = jpa.findFirstByFamilyIdOrderByCreatedAtDesc(familyId.toString())
                .orElseThrow(() -> new IllegalStateException("Familia desconocida: " + familyId));

        return crear(UUID.fromString(anterior.userId), UUID.fromString(anterior.appId), familyId);
    }

    private IssuedRefreshToken crear(UUID userId, UUID appId, UUID familyId) {
        var bytes = new byte[32];              // 256 bits
        ALEATORIO.nextBytes(bytes);
        var valor = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        var expira = Instant.now().plus(props.refreshTtl());

        var e = new RefreshTokenEntity();
        e.id = UUID.randomUUID().toString();
        e.userId = userId.toString();
        e.appId = appId.toString();
        e.tokenHash = sha256(valor);
        e.familyId = familyId.toString();
        e.expiresAt = expira;
        e.createdAt = Instant.now();
        jpa.save(e);

        return new IssuedRefreshToken(valor, familyId, expira);
    }

    @Override
    @Transactional
    public Optional<RefreshSubject> consume(String rawToken) {
        var encontrado = jpa.findByTokenHash(sha256(rawToken));
        if (encontrado.isEmpty()) {
            return Optional.empty();
        }
        var t = encontrado.get();
        var ahora = Instant.now();

        // Reutilización: el token ya se usó. Alguien tiene una copia, así que
        // cae la familia entera, incluido el token legítimo en circulación.
        if (t.usedAt != null) {
            jpa.revokeFamily(t.familyId, ahora);
            return Optional.empty();
        }
        if (t.revokedAt != null || t.expiresAt.isBefore(ahora)) {
            return Optional.empty();
        }

        t.usedAt = ahora;
        jpa.save(t);

        return Optional.of(new RefreshSubject(
                UUID.fromString(t.userId), UUID.fromString(t.appId), UUID.fromString(t.familyId)));
    }

    @Override
    @Transactional
    public void revokeFamily(UUID familyId) {
        jpa.revokeFamily(familyId.toString(), Instant.now());
    }

    private static String sha256(String valor) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(valor.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible en esta JVM.", e);
        }
    }
}
