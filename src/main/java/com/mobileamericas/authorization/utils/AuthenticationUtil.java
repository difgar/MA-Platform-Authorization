package com.mobileamericas.authorization.utils;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationUtil {

    private GoogleOAuthParamsConfig googleOAuthParamsConfig;

    public String getEmail() {
        return getEmail(SecurityContextHolder.getContext().getAuthentication());
    }

    public String getEmail(Authentication authentication) {
        return authentication.getPrincipal().toString();
    }

    public String getApp() {
        return getApp(SecurityContextHolder.getContext().getAuthentication());
    }

    public String getApp(Authentication authentication) {
        GoogleIdToken idToken = (GoogleIdToken)authentication.getCredentials();
        String clientId = idToken.getPayload().getAudience().toString();
        return googleOAuthParamsConfig.getApp(clientId);
    }
}
