package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code replicas: 1} es corrección funcional, no capacidad.
 *
 * Hermano de {@link EmisorDeProduccionTest}, y con el mismo molde (SnakeYAML
 * sobre kubernetes/deployment.yaml) por el mismo motivo: hasta aquí, lo único
 * que impedía subir las réplicas era un comentario, y una invariante que vive
 * sólo en un comentario no es una invariante. La revisión de rama pidió
 * convertirla en una que falle.
 *
 * Qué rompe subirlas: no hay ningún bean {@code OAuth2AuthorizationService},
 * así que las autorizaciones viven en memoria del pod
 * ({@code InMemoryOAuth2AuthorizationService}) y un código de autorización
 * emitido por un pod no se puede canjear en otro. Con dos réplicas y sin
 * sesión pegajosa, una fracción de los canjes falla con {@code invalid_grant},
 * de forma intermitente y sin que el error señale a ninguna parte.
 *
 * El mensaje de fallo dice qué hay que hacer ANTES de subirlo, y no sólo que
 * está prohibido: si no, lo único que aprende quien lo vea es a editar el test.
 */
class ReplicaUnicaTest {

    private static final Path DESPLIEGUE = Path.of("kubernetes/deployment.yaml");

    private static final String PRIMERO = """
            Antes de subir esto hace falta declarar un OAuth2AuthorizationService \
            persistente (un JdbcOAuth2AuthorizationService, que se intentó en la fase 2 \
            y se abortó: no sabe releer nuestro principal). Sin él, el código de \
            autorización vive en la memoria de UN pod y el canje falla de forma \
            intermitente en cuanto hay más de uno. El porqué entero, y contra qué se \
            choca, están en el README, sección «Réplicas». Si ya existe ese servicio, \
            este test se cambia con él, no antes.""";

    @Test
    void el_deployment_declara_una_sola_replica() throws IOException {
        assertThat(documento("Deployment").get("replicas"))
                .as("Deployment.spec.replicas. %s", PRIMERO)
                .isEqualTo(1);
    }

    @Test
    void el_hpa_no_puede_escalar_a_mas_de_una() throws IOException {
        var spec = documento("HorizontalPodAutoscaler");

        // Las dos, y no sólo maxReplicas: un minReplicas mayor que 1 escala
        // igual, sólo que sin esperar a la métrica.
        assertThat(spec.get("minReplicas"))
                .as("HPA.spec.minReplicas. %s", PRIMERO)
                .isEqualTo(1);
        assertThat(spec.get("maxReplicas"))
                .as("HPA.spec.maxReplicas: un HPA que pueda subir anula el 'replicas: 1' del "
                        + "Deployment sin tocarlo. %s", PRIMERO)
                .isEqualTo(1);
    }

    /** El bloque 'spec' del único documento de ese 'kind' en el fichero desplegado. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> documento(String kind) throws IOException {
        try (var in = Files.newInputStream(DESPLIEGUE)) {
            for (Object documento : new Yaml().loadAll(in)) {
                var mapa = (Map<String, Object>) documento;
                if (kind.equals(mapa.get("kind"))) {
                    return (Map<String, Object>) mapa.get("spec");
                }
            }
        }
        throw new AssertionError("no hay ningún " + kind + " en " + DESPLIEGUE);
    }
}
