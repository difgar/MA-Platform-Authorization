package com.mobileamericas.authorization.utils;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import com.mobileamericas.authorization.model.CustomUserDetail;
import com.mobileamericas.authorization.model.Role;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

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
        var credentials = authentication.getCredentials();

        if (credentials instanceof CustomUserDetail) {
            return ((CustomUserDetail)credentials).getApp();
        } else if (credentials instanceof GoogleIdToken) {
            return googleOAuthParamsConfig.getApp(((GoogleIdToken)credentials).getPayload().getAudience().toString());
        }

        return null;
    }

    public String getFullName() {
        return getFullName(SecurityContextHolder.getContext().getAuthentication());
    }

    public String getFullName(Authentication authentication) {
        var credentials = authentication.getCredentials();

        if (credentials instanceof CustomUserDetail) {
            return ((CustomUserDetail)credentials).getFullName();
        } else if (credentials instanceof GoogleIdToken) {
            return ((GoogleIdToken)credentials).getPayload().get("name").toString();
        }

        return null;
    }

    public List<Role> getRoles() {
        return getRoles(SecurityContextHolder.getContext().getAuthentication());
    }

    public List<Role> getRoles(Authentication authentication) {
        var credentials = authentication.getCredentials();

        if (credentials instanceof CustomUserDetail) {
            return ((CustomUserDetail)credentials).getRoles().stream().toList();
        } else if (credentials instanceof GoogleIdToken) {
            return List.of();
        }

        return null;
    }

    public String getAvatar() {
        return getAvatar(SecurityContextHolder.getContext().getAuthentication());
    }

    public String getAvatar(Authentication authentication) {
        var credentials = authentication.getCredentials();

        if (credentials instanceof CustomUserDetail) {
            return ((CustomUserDetail)credentials).getAvatar();
        } else if (credentials instanceof GoogleIdToken) {
            return ((GoogleIdToken)credentials).getPayload().get("picture").toString();
        }

        return null;
    }
}
