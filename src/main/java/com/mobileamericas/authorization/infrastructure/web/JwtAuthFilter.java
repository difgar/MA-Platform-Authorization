package com.mobileamericas.authorization.infrastructure.web;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobileamericas.authorization.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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
import java.util.Arrays;
import java.util.List;

@AllArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private static final String AUTH_HEADER_PREFIX = "Bearer ";
    private static final List<String> excludeUrls = List.of(".*/authorization/google.*", ".*/authorization/env.*", ".*/authorization/refresh-token.*");

    private String cookieAccessName;
    private ObjectMapper objectMapper;
    private AuthenticationManager authenticationManager;
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        if (excludeUrls.stream().anyMatch(path::matches)) {
            filterChain.doFilter(request, response);
            return;
        }

        String idTokenString = getToken(request);
        if (StringUtils.isNotBlank(idTokenString)) {
            try {
                DecodedJWT decodedJWT = jwtUtil.verifyAccessTokeAndGetDecoded(idTokenString);
                if (decodedJWT != null) {
                    Authentication authResult = this.authenticationManager.authenticate(
                            new PreAuthenticatedAuthenticationToken(decodedJWT.getIssuer(), jwtUtil.getUserDetail(decodedJWT)));

                    if(authResult.getAuthorities().isEmpty()) {
                        throw new AccessDeniedException(String.format("The user %s don't have roles or permissions", authResult.getPrincipal().toString()));
                    }
                    SecurityContextHolder.getContext().setAuthentication(authResult);
                } else {
                    throw new UsernameNotFoundException(String.format("Invalid token for the application"));
                }
            } catch (AccessDeniedException e) {
                var errorResponse = ResponseDto.error(String.format("Access denied, %s", e.getMessage()));
                response.sendError(HttpServletResponse.SC_FORBIDDEN, toJson(errorResponse));
                return;
            } catch (UsernameNotFoundException | JWTVerificationException e) {
                var errorResponse = ResponseDto.error(String.format("User not found, %s", e.getMessage()));
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, toJson(errorResponse));
                return;
            } catch (Exception e) {
                var errorResponse = ResponseDto.error(String.format("Error: %s", e.getMessage()), e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, toJson(errorResponse));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.startsWithIgnoreCase(authHeader, AUTH_HEADER_PREFIX)) {
            return authHeader.substring(AUTH_HEADER_PREFIX.length());
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            return Arrays.stream(cookies)
                    .filter(cookie -> cookieAccessName.equals(cookie.getName()))
                    .map(cookie -> cookie.getValue())
                    .findAny()
                    .orElse(null);
        }

        return null;
    }

    private String toJson(ResponseDto response) {
        try {
            return objectMapper.writeValueAsString(response);
        } catch (Exception e) {
            return "";
        }
    }
}
