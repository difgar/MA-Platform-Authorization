package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.adapter.token.JwtKeys;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
class JwksController {

    private final JwtKeys keys;

    JwksController(JwtKeys keys) {
        this.keys = keys;
    }

    /** Lo que consume MS-2 con spring.security.oauth2.resourceserver.jwt.jwk-set-uri. */
    @GetMapping("/.well-known/jwks.json")
    Map<String, Object> jwks() {
        return keys.publicJwks();
    }
}
