package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guardián de una duplicación que la revisión de la tarea 2 no dejó pasar en
 * silencio: {@code src/integrationTest/resources/application.yml} REEMPLAZA a
 * {@code classpath:application.yml} en vez de fusionarse con él (mismo nombre
 * de recurso, resuelto una sola vez), así que {@code spring.flyway.locations}
 * vive escrito dos veces -una por fichero- sin que nada compare los dos
 * valores. Dos registros que deben concordar sin que nada los compare es
 * exactamente la forma del bug que mantuvo este servicio caído -la razón por
 * la que esta fase entera puso el registro de clientes en {@code auth_app} en
 * vez de en la tabla propia del framework-, así que aquí se comparan.
 *
 * Se leen los ficheros por ruta de fichero, no por classpath: por classpath
 * los dos se llaman igual y sólo uno sería visible desde aquí, que es
 * precisamente el problema que esta prueba vigila.
 *
 * Si esta prueba falla, NO iguales el valor sin más: averigua cuál de los dos
 * ficheros cambió y si el otro también debía cambiar (por ejemplo, si la
 * tarea 9 mueve la ubicación otra vez).
 */
class FlywayLocationsCoherentesTest {

    private static final Path PRINCIPAL = Path.of("src/main/resources/application.yml");
    private static final Path INTEGRATION_TEST = Path.of("src/integrationTest/resources/application.yml");

    @SuppressWarnings("unchecked")
    private static String flywayLocations(Path yml) throws IOException {
        try (var in = Files.newInputStream(yml)) {
            var documento = (Map<String, Object>) new Yaml().load(in);
            var spring = (Map<String, Object>) documento.get("spring");
            var flyway = (Map<String, Object>) spring.get("flyway");
            return (String) flyway.get("locations");
        }
    }

    @Test
    void spring_flyway_locations_no_ha_divergido_entre_los_dos_ficheros() throws IOException {
        assertThat(flywayLocations(INTEGRATION_TEST))
                .as("%s reemplaza a %s durante integrationTest (mismo nombre de "
                        + "recurso): si difieren, la suite de dos motores corre "
                        + "contra una ubicación de migraciones distinta de la que "
                        + "usará producción, sin que nada lo avise",
                        INTEGRATION_TEST, PRINCIPAL)
                .isEqualTo(flywayLocations(PRINCIPAL));
    }
}
