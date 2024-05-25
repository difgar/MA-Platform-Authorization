package com.mobileamericas.authorization.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobileamericas.authorization.model.CustomUserDetail;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtil {

    public final static String CLAIM_NAME = "name";
    public final static String CLAIM_ROLES = "roles";
    public final static String CLAIM_AVATAR = "avatar";
    @Autowired
    private AuthenticationUtil authenticationUtil;
    @Autowired
    private ObjectMapper objectMapper;

    @Value("${authentication.jwt.secret}")
    private String JWT_SECRET;
    @Value("${authentication.cookie.access.name}")
    private String COOKIE_ACCESS_NAME;
    @Value("${authentication.cookie.refresh.name}")
    private String COOKIE_REFRESH_NAME;
    @Value("${authentication.cookie.access.expiration}")
    private Integer COOKIE_ACCESS_EXPIRATION;
    @Value("${authentication.cookie.refresh.expiration}")
    private Integer COOKIE_REFRESH_EXPIRATION;

    public Cookie createAccessCookieWithToken() {
        return createAccessCookie(createAccessToken());
    }

    public Cookie createRefreshCookieWithToken() {
        return createRefreshCookie(createRefreshToken());
    }

    public String createAccessToken() {
        return createAccessToken(
                authenticationUtil.getEmail(),
                authenticationUtil.getApp(),
                Map.of(CLAIM_NAME, authenticationUtil.getFullName(),
                        CLAIM_AVATAR, authenticationUtil.getAvatar(),
                        CLAIM_ROLES,  authenticationUtil.getRoles().stream()
                                .map(role -> Map.of(role.getName(), role.getPermissions().stream().collect(Collectors.toList())))
                                .collect(Collectors.toList())
                )
        );
    }

    public String createAccessToken(String email, String app, Map<String, ?> claims) {
        return JWT.create()
                .withIssuer(email)
                .withAudience(app)
                .withPayload(claims)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + COOKIE_ACCESS_EXPIRATION))
                .withJWTId(UUID.randomUUID().toString())
                .sign(Algorithm.HMAC512(Base64.getEncoder().encode(JWT_SECRET.getBytes())));
    }

    public String createRefreshToken() {
        return createRefreshToken(authenticationUtil.getEmail(), authenticationUtil.getApp());
    }

    public String createRefreshToken(String email, String app) {
        return JWT.create()
                .withIssuer(email)
                .withAudience(app)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + COOKIE_REFRESH_EXPIRATION))
                .withJWTId(UUID.randomUUID().toString())
                .sign(Algorithm.HMAC256(JWT_SECRET));
    }

    public Cookie refreshAccessToken(String accessToken, String refreshToken) {
        DecodedJWT decodedAuthToken = JWT.decode(accessToken);
            verifyRefreshTokeAndGetDecoded(refreshToken);

        String newAccessToken = createAccessToken(
                decodedAuthToken.getIssuer(),
                decodedAuthToken.getAudience().stream().findAny().orElse(null),
                mapClaims(decodedAuthToken.getClaims())
        );
        return createAccessCookie(newAccessToken);
    }

    public Cookie createAccessCookie(String token) {
        Cookie cookie = new Cookie(COOKIE_ACCESS_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(Math.toIntExact(TimeUnit.MILLISECONDS.toSeconds(COOKIE_ACCESS_EXPIRATION)));
        return cookie;
    }

    public Cookie createRefreshCookie(String token) {
        Cookie cookie = new Cookie(COOKIE_REFRESH_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(Math.toIntExact(TimeUnit.MILLISECONDS.toSeconds(COOKIE_REFRESH_EXPIRATION)));
        return cookie;
    }

    public DecodedJWT verifyAccessTokeAndGetDecoded(final String token) {
        Algorithm algorithm = Algorithm.HMAC512(Base64.getEncoder().encode(JWT_SECRET.getBytes()));
        JWTVerifier verifier = JWT.require(algorithm)
                //.withAudience(AUDIENCE)
                .build();
        return verifier.verify(token);
    }

    public DecodedJWT verifyRefreshTokeAndGetDecoded(final String token) {
        Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
        JWTVerifier verifier = JWT.require(algorithm)
                //.withAudience(AUDIENCE)
                .build();
        return verifier.verify(token);
    }

    public CustomUserDetail getUserDetail(DecodedJWT decodedJWT) {
        return CustomUserDetail.customBuilder()
                .username(decodedJWT.getIssuer())
                .password(decodedJWT.getAudience().stream().findAny().orElse(null))
                .authorities(List.of())
                .app(decodedJWT.getAudience().stream().findAny().orElse(null))
                .fullName(decodedJWT.getClaim(CLAIM_NAME).asString())
                .avatar(decodedJWT.getClaim(CLAIM_AVATAR).asString())
                .roles(Set.of())
                .build();
    }

    private Map<String, ?> mapClaims(Map<String, Claim> claims) {
        return Map.of(CLAIM_NAME, claims.get(CLAIM_NAME).asString(),
                CLAIM_AVATAR, claims.get(CLAIM_AVATAR).asString(),
                CLAIM_ROLES, claims.get(CLAIM_ROLES).asList(Map.class));
    }
}
