package com.mobileamericas.authorization.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reproduce, y comprueba que ya no se puede reproducir, el hallazgo de la
 * revisión de la ronda 1 del Task 10: {@code SecurityConfig.actuatorFilterChain()}
 * permitía sin autenticar CUALQUIER endpoint de management que
 * {@code management.endpoints.web.exposure.include} expusiera en cada
 * momento ({@code EndpointRequest.toAnyEndpoint()}), así que la única barrera
 * real entre {@code /actuator/env} y la red del pod era una lista en
 * application.yml, no la propia cadena de seguridad — un guardia cuya
 * protección vive en otro fichero es peor que ningún guardia.
 *
 * Un solo motor a propósito, no un par MySql/Postgres como
 * {@code SeguridadIT}: el comportamiento bajo prueba es enteramente de
 * Spring Security (qué RequestMatcher decide qué cadena aplica), no toca la
 * base de datos más allá de lo que cualquier arranque de contexto completo ya
 * necesita. Duplicarlo por motor no añadiría ninguna cobertura real, solo
 * tiempo de build.
 *
 * La propiedad de exposición se sobrescribe a propósito para incluir 'env':
 * la prueba obvia (pedir /actuator/env con la exposición POR DEFECTO,
 * health+info) habría dado 404 —Boot ni siquiera registra el endpoint— y eso
 * NO demuestra que la cadena de seguridad lo bloquee; es exactamente el
 * defecto de "una_ruta_no_declarada_exige_autenticacion" (task 9) repetido
 * aquí: una prueba que pasaría igual con o sin el control que dice verificar.
 * Exponer 'env' explícitamente simula el escenario real que motivó el
 * hallazgo (alguien lo añade a la lista para depurar un incidente) y prueba
 * que el matcher, fijado ahora a HealthEndpoint/InfoEndpoint por nombre, lo
 * sigue rechazando independientemente de esa lista.
 */
@Testcontainers
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "management.server.port=0",
                "management.endpoints.web.exposure.include=health,info,env"
        })
class ActuatorSecurityIT {

    @Container
    @ServiceConnection
    static MySQLContainer<?> db = new MySQLContainer<>("mysql:8.4");

    @Value("${local.management.port}")
    int managementPort;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void env_expuesto_sin_querer_sigue_exigiendo_autenticacion() throws Exception {
        // Con exposure.include ampliado a mano para incluir 'env', Boot SÍ
        // registra el endpoint (a diferencia del escenario con la exposición
        // por defecto). Lo que se comprueba aquí es que, aun así, sigue sin
        // dar 200: el matcher de actuatorFilterChain() no lo cubre, así que
        // cae en el anyRequest().authenticated() de filterChain().
        //
        // El rechazo lo pone el AuthenticationEntryPoint de la cadena de
        // cierre, y ése depende del mecanismo de autenticación que tenga
        // configurado: con la emisión propia de la fase 1 era el del resource
        // server (401 con WWW-Authenticate: Bearer); sin ningún mecanismo fue
        // un rato el 403 por defecto de Spring Security; y desde que la cadena
        // de cierre tiene oauth2Login con un solo proveedor, es la redirección
        // al login. Lo que esta prueba vigila no es cuál de los tres toca,
        // sino que /actuator/env no quede abierto: con un permitAll aquí
        // saldría un 200 con el entorno del proceso dentro.
        var respuesta = get("/actuator/env");

        assertThat(respuesta.statusCode()).isEqualTo(302);
        assertThat(respuesta.headers().firstValue("Location").orElseThrow())
                .endsWith("/oauth2/authorization/google");
        assertThat(respuesta.body())
                .as("nada del entorno del proceso debe salir por aquí")
                .doesNotContain("propertySources");
    }

    @Test
    void liveness_sigue_sin_autenticar() throws Exception {
        var respuesta = get("/actuator/health/liveness");

        assertThat(respuesta.statusCode()).isEqualTo(200);
        assertThat(respuesta.body()).contains("\"status\":\"UP\"");
    }

    @Test
    void readiness_sigue_sin_autenticar() throws Exception {
        // La prueba que de verdad importa para las sondas de Cloud Run (terraform/servicio.tf):
        // si esto exige autenticación, ningún pod pasa nunca su readinessProbe
        // (ver el hallazgo original del Task 10, antes de esta corrección).
        var respuesta = get("/actuator/health/readiness");

        assertThat(respuesta.statusCode()).isEqualTo(200);
        assertThat(respuesta.body()).contains("\"status\":\"UP\"");
    }

    @Test
    void info_sigue_sin_autenticar() throws Exception {
        var respuesta = get("/actuator/info");

        assertThat(respuesta.statusCode()).isEqualTo(200);
    }

    private HttpResponse<String> get(String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + managementPort + path))
                .GET()
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
