package com.mobileamericas.authorization.infrastructure.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.GeneralSecurityException;

@AllArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private static final String AUTH_HEADER_PREFIX = "Bearer ";
    private GoogleOAuthParamsConfig parameterProvider;
    private ObjectMapper objectMapper;
    private AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.startsWithIgnoreCase(authHeader, AUTH_HEADER_PREFIX)) {
            String idTokenString = authHeader.substring(AUTH_HEADER_PREFIX.length());
            try {
                GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                        .setAudience(parameterProvider.getClientIdList())
                        .build();

                GoogleIdToken idToken = verifier.verify(idTokenString);

                if (idToken != null) {
                    GoogleIdToken.Payload payload = idToken.getPayload();
                    String email = payload.getEmail();

                    Authentication authResult = this.authenticationManager.authenticate(new PreAuthenticatedAuthenticationToken(email, idToken));

                    if(authResult.getAuthorities().isEmpty()) {
                        throw new AccessDeniedException(String.format("The user %s don't have roles or permissions", email));
                    }
                    SecurityContextHolder.getContext().setAuthentication(authResult);
                } else {
                    throw new UsernameNotFoundException(String.format("Invalid token for the application"));
                }
            } catch (AccessDeniedException e) {
                var errorResponse = ResponseDto.error(String.format("Access denied, %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_FORBIDDEN, toJson(errorResponse));
                return;
            } catch (UsernameNotFoundException e) {
                var errorResponse = ResponseDto.error(String.format("User not found, %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, toJson(errorResponse));
                return;
            } catch (GeneralSecurityException e) {
                var errorResponse = ResponseDto.error(String.format("Invalid JWT token, %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, toJson(errorResponse));
                return;
            } catch (IOException e) {
                var errorResponse = ResponseDto.error(String.format("Error verifying JWT token, %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, toJson(errorResponse));
                return;
            } catch (Exception e) {
                var errorResponse = ResponseDto.error(String.format("Error: %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, toJson(errorResponse));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String toJson(ResponseDto response) {
        try {
            return objectMapper.writeValueAsString(response);
        } catch (Exception e) {
            return "";
        }
    }
}
