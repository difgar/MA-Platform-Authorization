package com.mobileamericas.authorization.web.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Prueba unitaria y sin contexto de Spring: la propia SecurityConfig hace de
 * fábrica de CorsConfigurationSource, así que basta con invocar el método.
 *
 * Existe porque setAllowedOriginPatterns() (a diferencia de setAllowedOrigins())
 * admite comodines junto con allowCredentials(true) sin que Spring lo rechace
 * al arrancar: CorsConfiguration.validateAllowCredentials() solo inspecciona
 * allowedOrigins, nunca allowedOriginPatterns. Sin la validación de
 * SecurityConfig.validarOrigenes(), un comodín demasiado amplio arrancaría
 * igual y el servicio reflejaría el Origin de cualquier llamador con
 * credenciales.
 *
 * El rechazo no es por el string literal '*': es por la POSICIÓN del comodín.
 * '*', 'https://*' y 'https://*.com' caen los tres por el mismo motivo (menos
 * de dos etiquetas después del comodín), no por coincidir con un caso
 * especial de cada uno.
 */
class SecurityConfigTest {

    private final SecurityConfig config = new SecurityConfig();

    @Test
    void rechaza_un_origen_comodin() {
        var props = new CorsProperties(List.of("*"));

        assertThatThrownBy(() -> config.corsConfigurationSource(props))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("allowed-origins");
    }

    @Test
    void rechaza_el_comodin_aunque_venga_junto_a_orígenes_válidos() {
        var props = new CorsProperties(List.of("https://admin.mobile-americas.com", "*"));

        assertThatThrownBy(() -> config.corsConfigurationSource(props))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rechaza_un_comodin_sin_ninguna_etiqueta_detras() {
        // Coincide con cualquier origen https, sin importar el dominio.
        var props = new CorsProperties(List.of("https://*"));

        assertThatThrownBy(() -> config.corsConfigurationSource(props))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rechaza_un_comodin_con_una_sola_etiqueta_detras() {
        // Coincide con cualquier origen de ese TLD: el mismo agujero que '*',
        // solo que con una forma que a simple vista parece más concreta.
        var props = new CorsProperties(List.of("https://*.com"));

        assertThatThrownBy(() -> config.corsConfigurationSource(props))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void acepta_patrones_concretos() {
        var props = new CorsProperties(List.of("https://*.mobile-americas.com"));

        assertThat(config.corsConfigurationSource(props)).isNotNull();
    }

    @Test
    void acepta_un_origen_exacto_sin_comodin() {
        var props = new CorsProperties(List.of("https://admin.mobile-americas.com"));

        assertThat(config.corsConfigurationSource(props)).isNotNull();
    }
}
