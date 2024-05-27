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
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
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
        return createAccessCookie(createAccessToken(), authenticationUtil.getApp());
    }

    public Cookie createRefreshCookieWithToken() {
        return createRefreshCookie(createRefreshToken(), authenticationUtil.getApp());
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

    public Cookie refreshAccessToken(Cookie[] cookies) {
        if(cookies == null) {
            return null;
        }

        String accessToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(getCoockieName(COOKIE_ACCESS_NAME, authenticationUtil.getApp())))
                .map(Cookie::getValue)
                .findAny()
                .orElse(null);

        String refreshToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(getCoockieName(COOKIE_REFRESH_NAME, authenticationUtil.getApp())))
                .map(Cookie::getValue)
                .findAny()
                .orElse(null);

        DecodedJWT decodedAuthToken = JWT.decode(accessToken);
        verifyRefreshTokeAndGetDecoded(refreshToken);
        var app = decodedAuthToken.getAudience().stream().findAny().orElse(null);

        String newAccessToken = createAccessToken(
                decodedAuthToken.getIssuer(),
                app,
                mapClaims(decodedAuthToken.getClaims())
        );
        return createAccessCookie(newAccessToken, app);
    }

    public Cookie createAccessCookie(String token, String app) {
        Cookie cookie = new Cookie(getCoockieName(COOKIE_ACCESS_NAME, app), token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setAttribute("SameSite", "Lax");
        cookie.setMaxAge(Math.toIntExact(TimeUnit.MILLISECONDS.toSeconds(COOKIE_ACCESS_EXPIRATION)));
        return cookie;
    }

    public Cookie createRefreshCookie(String token, String app) {
        Cookie cookie = new Cookie(getCoockieName(COOKIE_REFRESH_NAME, app), token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setAttribute("SameSite", "Lax");
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

    public List<Cookie> deleteCookies(Cookie[] cookies) {
        if(cookies == null) {
            return List.of();
        }

        return Arrays.stream(cookies)
                .map(cookie -> {
                    Cookie newCookie = new Cookie(cookie.getName(), null);
                    newCookie.setHttpOnly(true);
                    newCookie.setSecure(true);
                    newCookie.setPath("/");
                    newCookie.setMaxAge(0);
                    newCookie.setAttribute("SameSite", "Lax");
                    return newCookie;
                }).collect(Collectors.toList());
    }

    private Map<String, ?> mapClaims(Map<String, Claim> claims) {
        return Map.of(CLAIM_NAME, claims.get(CLAIM_NAME).asString(),
                CLAIM_AVATAR, claims.get(CLAIM_AVATAR).asString(),
                CLAIM_ROLES, claims.get(CLAIM_ROLES).asList(Map.class));
    }

    private String getCoockieName(String cookie, String app) {
        return StringUtils.join(app, StringUtils.capitalize(cookie));
    }
}
