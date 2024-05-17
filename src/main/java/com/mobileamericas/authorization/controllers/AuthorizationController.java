package com.mobileamericas.authorization.controllers;

import com.mobileamericas.authorization.infrastructure.config.GoogleOAuthParamsConfig;
import com.mobileamericas.authorization.infrastructure.web.ResponseDto;
import com.mobileamericas.authorization.services.AuthorizationService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/v1/authorization")
@AllArgsConstructor
public class AuthorizationController {

    private AuthorizationService authorizationService;
    private GoogleOAuthParamsConfig googleOAuthParamsConfig;

    @GetMapping("health-check")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OK");
    }

    @GetMapping("env")
    public ResponseEntity<ResponseDto> getEnv() {

        var list = List.of(
                googleOAuthParamsConfig.getClientList().stream().collect(Collectors.toList()),
                System.getProperties().entrySet().stream().collect(Collectors.toList()),
                System.getenv());

        return ResponseEntity.ok(ResponseDto.success(list));
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
