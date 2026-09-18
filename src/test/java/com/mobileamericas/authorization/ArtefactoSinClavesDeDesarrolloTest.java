package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarFile;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * La clave de desarrollo NO viaja en el artefacto que se despliega.
 *
 * Hermano de {@link EmisorDeProduccionTest} y de {@link FlywayLocationsCoherentesTest}:
 * lo que aquí se comprueba es una afirmación de seguridad escrita en tres
 * sitios -{@code bootJar { exclude 'dev-keys/**' }}, el comentario de
 * application-dev.yml y el README, sección «Generar una clave de firma»- que
 * hasta ahora no verificaba nadie. Una afirmación de seguridad que vive sólo
 * en comentarios no es una invariante.
 *
 * Lo que caza: que alguien quite el {@code exclude} (por ejemplo al tocar
 * bootJar para otra cosa) y el jar de producción pase a llevar dentro una
 * clave RSA privada commiteada en un repositorio, es decir la capacidad de
 * firmar tokens de este emisor.
 *
 * La ruta del jar la pasa build.gradle en 'ma.artefacto', y ahí está también
 * la dependencia que obliga a construirlo antes de esta suite.
 */
class ArtefactoSinClavesDeDesarrolloTest {

    private static final Path CLAVE_DE_DESARROLLO = Path.of("src/main/resources/dev-keys/active.jwk");

    @Test
    void el_jar_de_despliegue_no_lleva_la_clave_de_desarrollo() throws IOException {
        // Sin esto, el día que alguien borre la clave de desarrollo esta prueba
        // seguiría verde sin comprobar nada: no habría nada que excluir.
        assertThat(CLAVE_DE_DESARROLLO)
                .as("si %s ya no existe, este test sobra; mientras exista, el jar no puede llevarla",
                        CLAVE_DE_DESARROLLO)
                .exists();

        var jar = Path.of(System.getProperty("ma.artefacto", ""));
        assertThat(Files.isRegularFile(jar))
                .as("build.gradle tiene que pasar en 'ma.artefacto' el jar ya construido, y pasó '%s'", jar)
                .isTrue();

        try (var artefacto = new JarFile(jar.toFile())) {
            var entradas = artefacto.stream().map(e -> e.getName()).toList();

            // Control positivo: sin él, un jar vacío o abierto por la ruta
            // equivocada pasaría esta prueba por no contener nada.
            assertThat(entradas)
                    .as("el jar tiene que traer los recursos de la aplicación; si no, la ausencia "
                            + "de dev-keys/ no demuestra nada")
                    .contains("BOOT-INF/classes/application.yml");
            assertThat(entradas)
                    .as("una clave privada commiteada no puede viajar en el artefacto que se "
                            + "despliega: quien lo tenga puede firmar tokens de este emisor")
                    .noneMatch(nombre -> nombre.contains("dev-keys/"));
        }
    }
}
