package com.mobileamericas.authorization.adapter.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authorization.google")
public record GoogleProperties(String jwkSetUri, String issuer) {

    public GoogleProperties {
        jwkSetUri = jwkSetUri == null ? "https://www.googleapis.com/oauth2/v3/certs" : jwkSetUri;
        issuer = issuer == null ? "https://accounts.google.com" : issuer;
    }
}
