package com.mobileamericas.authorization.controllers;

import com.mobileamericas.authorization.infrastructure.web.ResponseDto;
import com.mobileamericas.authorization.services.AuthorizationService;
import com.mobileamericas.authorization.services.GoogleOAuthService;
import com.mobileamericas.authorization.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/v1/authorization")
@AllArgsConstructor
@Slf4j
public class AuthorizationController {

    private AuthorizationService authorizationService;
    private GoogleOAuthService googleOAuthService;
    private JwtUtil jwtUtil;

    @GetMapping("/health-check")
    public ResponseEntity<String> healthCheck() {
        log.info("/health-check");
        return ResponseEntity.ok("OK");
    }

    @GetMapping("/env")
    public ResponseEntity<ResponseDto> getEnv() {
        log.info("/env");
        var list = List.of(
                googleOAuthService.getMapClientIds(),
                System.getProperties().entrySet().stream().collect(Collectors.toList()),
                System.getenv());

        return ResponseEntity.ok(ResponseDto.success(list));
    }

    @PostMapping("/google")
    public ResponseEntity<ResponseDto> auth(@RequestBody String token, final HttpServletRequest request, final HttpServletResponse response) throws GeneralSecurityException, IOException {
        log.info("/google {}", token);
        var domain = getDomainToCookie(request);
        googleOAuthService.validateToken(token);
        var accessCookie = jwtUtil.createAccessCookieWithToken();
        accessCookie.setDomain(domain);
        response.addCookie(accessCookie);

        var refreshCookie = jwtUtil.createRefreshCookieWithToken();
        refreshCookie.setDomain(domain);
        response.addCookie(refreshCookie);
        return ResponseEntity.ok(ResponseDto.success("OK"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseDto> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        log.info("/refresh-token");
        var domain = getDomainToCookie(request);
        var accessCookie = jwtUtil.refreshAccessToken(request.getCookies());
        accessCookie.setDomain(domain);
        response.addCookie(accessCookie);
        return ResponseEntity.ok(ResponseDto.success("OK"));
    }

    @GetMapping("/logout")
    public ResponseEntity<ResponseDto> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("/logout");
        var domain = getDomainToCookie(request);
        jwtUtil.deleteCookies(request.getCookies())
                .forEach(cookie -> {
                    cookie.setDomain(domain);
                    response.addCookie(cookie);});

        return ResponseEntity.ok(ResponseDto.success("OK"));
    }

    @GetMapping("/role")
    public ResponseEntity<ResponseDto> getRoles() {
        log.info("/role");
        return authorizationService.getRoles()
                .map(roles -> ResponseEntity.ok(ResponseDto.success(roles)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ResponseDto.error(String.format("Roles not found to user:%s", getUserName()))));
    }

    @PostMapping()
    public ResponseEntity<ResponseDto> createRoles() {
        return ResponseEntity.ok(ResponseDto.success("Rol created OK"));
    }

    @PutMapping()
    public ResponseEntity<ResponseDto> updateRoles() {
        return ResponseEntity.ok(ResponseDto.success("Rol updated OK"));
    }

    private String getUserName() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
    }
    
    private String getDomainToCookie(final HttpServletRequest request) {
        String origin = request.getServerName();
        String[] parts = StringUtils.split(origin, '.');
        if (parts.length >= 3) {
            return parts[parts.length - 2].concat(".").concat(parts[parts.length - 1]);
        }
        return origin;
    }
}
