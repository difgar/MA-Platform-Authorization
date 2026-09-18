package com.mobileamericas.authorization.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Errores en application/problem+json (RFC 7807).
 *
 * El ResponseDto anterior metía e.getStackTrace()[0] en el cuerpo, filtrando
 * rutas de clases y números de línea a quien llamara. Aquí la traza va al log y
 * al cliente solo le llega el motivo.
 *
 * Extiende {@link ResponseEntityExceptionHandler} a propósito: sin eso,
 * {@code @ExceptionHandler(Exception.class)} de más abajo intercepta ANTES que
 * {@code ResponseStatusExceptionResolver} y {@code DefaultHandlerExceptionResolver},
 * así que una excepción de Spring MVC con su propio status —por ejemplo
 * un parámetro obligatorio ausente en una ruta pública— se convertía en 500
 * con traza en el log en vez del 400 que le corresponde. Como esas rutas son
 * públicas, cualquier llamador anónimo podía forzar trazas ERROR en el log a
 * voluntad con solo omitir el parámetro: el objetivo era mandar la traza al
 * log, no dejar que un extraño decida cuándo se escribe.
 * ResponseEntityExceptionHandler ya sabe traducir esas excepciones
 * (ServletRequestBindingException, HttpRequestMethodNotSupportedException,
 * NoResourceFoundException...) a su ProblemDetail correcto; los manejadores de
 * más abajo siguen ganando por ser más específicos.
 */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /**
     * NO se traduce aquí: se relanza a propósito.
     *
     * org.springframework.security.access.AccessDeniedException es la que
     * lanza un método protegido con @PreAuthorize (habilitado por
     * @EnableMethodSecurity en SecurityConfig). Esa excepción nace DENTRO de
     * la invocación del controlador, en el mismo hilo y la misma pila que
     * @ExceptionHandler(Exception.class); si se atrapara ahí, quedaría resuelta
     * como un ProblemDetail normal dentro del despachador, y
     * ExceptionTranslationFilter —que vive en la cadena de filtros, fuera del
     * despachador— nunca llegaría a verla. El resultado sería un 500 donde
     * Spring Security da un 403. Relanzar hace que este resolver "falle" (en
     * el sentido de Spring) y la excepción original suba por la pila hasta la
     * cadena de filtros, donde corresponde traducirla.
     */
    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    void accesoDenegadoPorSpringSecurity(org.springframework.security.access.AccessDeniedException e)
            throws org.springframework.security.access.AccessDeniedException {
        throw e;
    }

    /** Mismo motivo que el de arriba, para el otro lado del filtro: AuthenticationException. */
    @ExceptionHandler(AuthenticationException.class)
    void credencialesInvalidasPorSpringSecurity(AuthenticationException e) throws AuthenticationException {
        throw e;
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
