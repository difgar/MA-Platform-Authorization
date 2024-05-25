package com.mobileamericas.authorization.services.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import com.mobileamericas.authorization.services.GoogleOAuthService;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class GoogleOAuthServiceImpl implements GoogleOAuthService {

    private GoogleOAuthParamsConfig parameterProvider;
    private AuthenticationManager authenticationManager;

    @Override
    public void validateToken(String token) throws GeneralSecurityException, IOException {

        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("The token is required");
        }

        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(parameterProvider.getClientIdList())
                    .build();

            GoogleIdToken idToken = verifier.verify(token);

            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();
                String email = payload.getEmail();

                Authentication authResult = this.authenticationManager.authenticate(new PreAuthenticatedAuthenticationToken(email, idToken));

                if (authResult.getAuthorities().isEmpty()) {
                    throw new AccessDeniedException(String.format("The user %s don't have roles or permissions", email));
                }
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } else {
                throw new AccessDeniedException("Invalid token for the application");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(Objects.toString(e.getMessage(), "Invalid token"));
        }
    }

    @Override
    public List<Map<String,String>> getMapClientIds() {
        return parameterProvider.getClientList().stream().collect(Collectors.toList());
    }
}
