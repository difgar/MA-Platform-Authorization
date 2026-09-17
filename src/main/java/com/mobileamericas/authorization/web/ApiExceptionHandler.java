package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Errores en application/problem+json (RFC 7807).
 *
 * El ResponseDto anterior metía e.getStackTrace()[0] en el cuerpo, filtrando
 * rutas de clases y números de línea a quien llamara. Aquí la traza va al log y
 * al cliente solo le llega el motivo.
 */
@RestControllerAdvice
class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(IdentityVerifier.IdentityRejectedException.class)
    ProblemDetail identidadRechazada(IdentityVerifier.IdentityRejectedException e) {
        log.info("Identidad rechazada: {}", e.getMessage());
        var p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, e.getMessage());
        p.setTitle("Identidad no válida");
        return p;
    }

    @ExceptionHandler(AuthenticationService.AccessDeniedException.class)
    ProblemDetail accesoDenegado(AuthenticationService.AccessDeniedException e) {
        log.info("Acceso denegado: {}", e.getMessage());
        var p = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
        p.setTitle("Acceso denegado");
        return p;
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail inesperado(Exception e) {
        log.error("Error no controlado", e);
        var p = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "Error interno.");
        p.setTitle("Error interno");
        return p;
    }
}
