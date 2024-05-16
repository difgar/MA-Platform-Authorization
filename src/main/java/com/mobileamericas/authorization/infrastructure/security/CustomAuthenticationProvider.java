package com.mobileamericas.authorization.infrastructure.security;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private AuthenticationUserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getPrincipal().toString();
        GoogleIdToken idToken = (GoogleIdToken)authentication.getCredentials();
        String clientId = idToken.getPayload().getAudience().toString();

        UserDetails userDetails = userDetailsService.loadUserDetails(authentication);
        return new PreAuthenticatedAuthenticationToken(userDetails.getUsername(), idToken, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
