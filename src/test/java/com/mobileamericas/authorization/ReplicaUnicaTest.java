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
 * Hermano de {@link EmisorDeProduccionTest}, y con el mismo molde (el despliegue de
 * producción, hoy terraform/servicio.tf en Cloud Run; antes kubernetes/deployment.yaml
 * con replicas 1 y HPA 1..1) por el mismo motivo: hasta aquí, lo único
 * que impedía subir las réplicas era un comentario, y una invariante que vive
 * sólo en un comentario no es una invariante. La revisión de rama pidió
 * convertirla en una que falle.
 *
 * Qué rompe subirlas: no hay ningún bean {@code OAuth2AuthorizationService},
 * así que las autorizaciones viven en memoria de la instancia
 * ({@code InMemoryOAuth2AuthorizationService}) y un código de autorización
 * emitido por un pod no se puede canjear en otro. Con dos réplicas y sin
 * sesión pegajosa, una fracción de los canjes falla con {@code invalid_grant},
 * de forma intermitente y sin que el error señale a ninguna parte.
 *
 * El mensaje de fallo dice qué hay que hacer ANTES de subirlo, y no sólo que
 * está prohibido: si no, lo único que aprende quien lo vea es a editar el test.
 */
class ReplicaUnicaTest {

    private static final String PRIMERO = """
            Antes de subir esto hace falta declarar un OAuth2AuthorizationService \
            persistente (un JdbcOAuth2AuthorizationService, que se intentó en la fase 2 \
            y se abortó: no sabe releer nuestro principal). Sin él, el código de \
            autorización vive en la memoria de UN pod y el canje falla de forma \
            intermitente en cuanto hay más de uno. El porqué entero, y contra qué se \
            choca, están en el README, sección «Réplicas». Si ya existe ese servicio, \
            este test se cambia con él, no antes.""";

    @Test
    void cloud_run_arranca_con_una_instancia() throws IOException {
        assertThat(TerraformDelAuth.escalado("min_instance_count"))
                .as("Cloud Run min_instance_count. %s", PRIMERO)
                .isEqualTo(1);
    }

    @Test
    void cloud_run_no_puede_escalar_a_mas_de_una() throws IOException {
        // Lo que en GKE era el HPA 1..1: un maximo mayor que 1 reparte los canjes entre
        // instancias sin tocar nada mas.
        assertThat(TerraformDelAuth.escalado("max_instance_count"))
                .as("Cloud Run max_instance_count: con mas de una, el canje falla de forma "
                        + "intermitente. %s", PRIMERO)
                .isEqualTo(1);
    }
}
