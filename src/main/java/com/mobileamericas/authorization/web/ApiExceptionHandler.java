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
 * ALCANCE REAL, que esta fase cambió: un @RestControllerAdvice sólo alcanza lo
 * que despacha DispatcherServlet, y desde que la fase 2 borró AuthController y
 * MeController NO queda ningún @Controller ni @RestController en src/main. Los
 * endpoints de OAuth y OIDC no son controladores: son filtros de la cadena de
 * seguridad, con sus propios manejadores de error -responden el JSON de error
 * de OAuth 2.0, no un ProblemDetail-, así que nada de lo de aquí les aplica.
 * Lo único que este advice puede llegar a tocar hoy es BasicErrorController
 * (/error), y por ahí no pasa ninguna excepción propia.
 *
 * Se mantiene porque es el valor por defecto correcto para cuando vuelva a
 * haber controladores (el CRUD de aplicaciones de la fase 3) y porque los dos
 * relanzamientos de más abajo son sutiles: si desaparece este fichero,
 * reaparecen los dos fallos que documentan. Lo que ya NO describe la realidad
 * -y por eso se reescribió este párrafo- es el razonamiento anterior, que
 * hablaba de rutas públicas con parámetros obligatorios que un llamador anónimo
 * podía usar para forzar trazas ERROR: esas rutas se fueron con la fase 1.
 *
 * Extiende {@link ResponseEntityExceptionHandler} a propósito, y el motivo
 * sigue siendo válido para esos controladores futuros: sin eso,
 * {@code @ExceptionHandler(Exception.class)} de más abajo intercepta ANTES que
 * {@code ResponseStatusExceptionResolver} y {@code DefaultHandlerExceptionResolver},
 * así que una excepción de Spring MVC con su propio status —por ejemplo un
 * parámetro obligatorio ausente— se convertiría en 500 con traza en el log en
 * vez del 400 que le corresponde. ResponseEntityExceptionHandler ya sabe
 * traducir esas excepciones (ServletRequestBindingException,
 * HttpRequestMethodNotSupportedException, NoResourceFoundException...) a su
 * ProblemDetail correcto; los manejadores de más abajo siguen ganando por ser
 * más específicos.
 */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /**
     * NO se traduce aquí: se relanza a propósito.
     *
     * org.springframework.security.access.AccessDeniedException es la que
     * lanza un método protegido con @PreAuthorize (habilitado por
     * @EnableMethodSecurity en SecurityConfig). Hoy no hay ningún método así
     * -no hay controladores-, con lo que esta rama no se recorre; queda escrita
     * porque el fallo que evita no se ve leyendo el código que lo provoca. Esa
     * excepción nace DENTRO de la invocación del controlador, en el mismo hilo
     * y la misma pila que
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
