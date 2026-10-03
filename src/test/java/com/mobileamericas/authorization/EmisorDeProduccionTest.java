package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * El VALOR del emisor, leído del fichero que se despliega.
 *
 * Hermano de {@link FlywayLocationsCoherentesTest}, y por el mismo motivo: hay
 * cosas de la configuración que ninguna prueba con contexto puede afirmar. El
 * mecanismo -que Spring Authorization Server respete la propiedad- lo cubre
 * DescubrimientoIT con @TestPropertySource. Lo que NO puede cubrir es el valor
 * de producción: la suite corre en un puerto aleatorio, así que fijar ahí el
 * emisor real rompería el documento de descubrimiento de las propias pruebas.
 *
 * Las dos regresiones que caza este test son reales y distintas de esa:
 *
 * 1. Que alguien le devuelva un valor por defecto a AUTH_ISSUER. El anterior
 *    era la URL de producción, así que un entorno que olvidara la variable
 *    arrancaba emitiendo el 'iss' de producción sin que nada fallara. Fallar
 *    cerrado aquí es lo que convierte ese olvido en un pod que no arranca.
 * 2. Que alguien quite el context path del emisor de producción (terraform/variables.tf;
 *    antes, el ConfigMap de kubernetes/deployment.yaml). Los endpoints
 *    cuelgan de él, así que un emisor sin /authorization-api anuncia URL que
 *    no existen y rompe a todo consumidor que use issuer-uri.
 *
 * Se lee por ruta de fichero y no por classpath, igual que el hermano: por
 * classpath, application.yml de integrationTest tapa al principal.
 */
class EmisorDeProduccionTest {

    private static final Path PRINCIPAL = Path.of("src/main/resources/application.yml");
    private static final Path DEV = Path.of("src/main/resources/application-dev.yml");

    private static final String PROPIEDAD = "spring.security.oauth2.authorizationserver.issuer";
    private static final String CONTEXT_PATH = "/authorization-api";

    @Test
    void el_emisor_no_tiene_valor_por_defecto_en_el_perfil_por_defecto() throws IOException {
        assertThat(emisorDe(PRINCIPAL))
                .as("""
                        %s tiene que exigir AUTH_ISSUER sin default: con uno, un entorno \
                        que olvide la variable arranca emitiendo el 'iss' de otro entorno \
                        y nada falla. Si necesitas un default, el resto de este fichero \
                        explica por qué no.""", PRINCIPAL)
                .isEqualTo("${AUTH_ISSUER}");
    }

    @Test
    void el_emisor_de_produccion_lleva_el_context_path() throws IOException {
        var emisor = TerraformDelAuth.porDefecto("issuer");

        assertThat(emisor)
                .as("el emisor es la base de todas las URL del descubrimiento, y los "
                        + "endpoints cuelgan del context path %s", CONTEXT_PATH)
                .startsWith("https://")
                .endsWith(CONTEXT_PATH);
    }

    /**
     * El default de variables.tf no basta: un *.tfvars que fije 'issuer' lo pisa sin tocar
     * ese fichero, y los otros tests seguirian en verde con produccion rota (revision
     * final, 2026-10-03). El emisor se cambia en variables.tf, a la vista de este test.
     */
    @Test
    void ningun_tfvars_pisa_el_emisor() throws IOException {
        assertThat(TerraformDelAuth.tfvarsQueFijan("issuer"))
                .as("estos ficheros fijan 'issuer' y pisarian el default vigilado de variables.tf")
                .isEmpty();
    }

    /**
     * El redirect_uri de Google sufre exactamente lo mismo que el emisor, y
     * además tiene que coincidir carácter a carácter con lo registrado en la
     * consola de Google Cloud: si no, el login cae entero.
     */
    @Test
    void el_redirect_uri_de_google_cuelga_del_mismo_emisor() throws IOException {
        assertThat(TerraformDelAuth.env("AUTH_ISSUER")).isEqualTo("var.issuer");
        assertThat(TerraformDelAuth.env("GOOGLE_REDIRECT_URI"))
                .isEqualTo("${var.issuer}/login/oauth2/code/google");
    }

    @Test
    void el_perfil_dev_fija_su_propio_emisor_local() throws IOException {
        assertThat(emisorDe(DEV))
                .as("sin sobrescribirlo, 'dev' heredaría el placeholder de producción y "
                        + "no arrancaría; y con el valor de producción emitiría tokens de "
                        + "producción desde localhost")
                .startsWith("http://localhost:")
                .endsWith(CONTEXT_PATH);
    }

    @SuppressWarnings("unchecked")
    private static String emisorDe(Path yml) throws IOException {
        try (var in = Files.newInputStream(yml)) {
            Map<String, Object> documento = new Yaml().load(in);
            var spring = (Map<String, Object>) documento.get("spring");
            // La clave está escrita en forma punteada ('security.oauth2.
            // authorizationserver'), que Spring aplana al cargar pero SnakeYAML
            // devuelve tal cual como una clave literal.
            var bloque = (Map<String, Object>) spring.get("security.oauth2.authorizationserver");
            assertThat(bloque).as("%s no declara %s", yml, PROPIEDAD).isNotNull();
            return (String) bloque.get("issuer");
        }
    }
}
