package com.mobileamericas.authorization.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/auth")
class MeController {

    /**
     * Todo sale del token ya validado: no hace falta tocar la base de datos.
     *
     * Un {@code Map.of(...)} revienta con {@link NullPointerException} en cuanto
     * uno de sus valores es null, y aquí 'name' puede faltar de verdad: full_name
     * es NULLABLE en el esquema, y RsaTokenIssuer omite el claim 'name' cuando no
     * hay nombre en vez de mandarlo nulo o vacío (ver su comentario). Un record
     * no tiene el problema de Map.of: 'name' pasa tal cual, null incluido, sin
     * fabricar un "" que le haría creer a quien llama que el nombre se conoce y
     * está vacío. Los demás claims opcionales (roles, permissions, app) sí se
     * cubren con un valor por defecto porque su ausencia no es un dato honesto
     * que valga la pena preservar aquí.
     */
    @GetMapping("/me")
    MeResponse me(@AuthenticationPrincipal Jwt jwt) {
        var audiencia = jwt.getAudience();
        var roles = jwt.getClaimAsStringList("roles");
        var permisos = jwt.getClaimAsStringList("permissions");

        return new MeResponse(
                jwt.getSubject(),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("name"),
                (audiencia == null || audiencia.isEmpty()) ? null : audiencia.getFirst(),
                roles == null ? List.of() : roles,
                permisos == null ? List.of() : permisos);
    }

    record MeResponse(String id, String email, String name, String app,
                       List<String> roles, List<String> permissions) {}
}
