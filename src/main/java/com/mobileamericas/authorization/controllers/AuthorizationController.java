package com.mobileamericas.authorization.controllers;

import com.mobileamericas.authorization.infrastructure.web.ResponseDto;
import com.mobileamericas.authorization.services.AuthorizationService;
import com.mobileamericas.authorization.services.GoogleOAuthService;
import com.mobileamericas.authorization.utils.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/v1/authorization")
@AllArgsConstructor
@CrossOrigin("*")
public class AuthorizationController {

    private final static String COOKIE_ACCESS_NAME = "accessToken";
    private final static String COOKIE_REFRESH_NAME = "refreshToken";

    private AuthorizationService authorizationService;
    private GoogleOAuthService googleOAuthService;
    private JwtUtil jwtUtil;

    @GetMapping("health-check")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OK");
    }

    @GetMapping("env")
    public ResponseEntity<ResponseDto> getEnv() {
        var list = List.of(
                googleOAuthService.getMapClientIds(),
                System.getProperties().entrySet().stream().collect(Collectors.toList()),
                System.getenv());

        return ResponseEntity.ok(ResponseDto.success(list));
    }

    @PostMapping("google")
    public ResponseEntity<ResponseDto> auth(@RequestBody String token, final HttpServletResponse response) throws GeneralSecurityException, IOException {
        googleOAuthService.validateToken(token);
        response.addCookie(jwtUtil.createAccessCookieWithToken());
        response.addCookie(jwtUtil.createRefreshCookieWithToken());
        return ResponseEntity.ok(ResponseDto.success("OK"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseDto> refreshToken(@CookieValue(value = COOKIE_ACCESS_NAME, required = false) String accessToken,
                                                    @CookieValue(value = COOKIE_REFRESH_NAME, required = false) String refreshToken,
                                                    HttpServletResponse response) {
        if (accessToken == null || refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ResponseDto.error("Refresh token is missing"));
        }
        response.addCookie(jwtUtil.refreshAccessToken(accessToken, refreshToken));
        return ResponseEntity.ok(ResponseDto.success("OK"));
    }

    @GetMapping("role")
    public ResponseEntity<ResponseDto> getRoles() {
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
}
