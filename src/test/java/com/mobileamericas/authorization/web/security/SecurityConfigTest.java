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
 * admite '*' junto con allowCredentials(true) sin que Spring lo rechace al
 * arrancar: CorsConfiguration.validateAllowCredentials() solo inspecciona
 * allowedOrigins, nunca allowedOriginPatterns. Sin este rechazo explícito,
 * authorization.cors.allowed-origins: '*' arrancaría igual y el servicio
 * reflejaría el Origin de cualquier llamador con credenciales.
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
    void acepta_patrones_concretos() {
        var props = new CorsProperties(List.of("https://*.mobile-americas.com"));

        assertThat(config.corsConfigurationSource(props)).isNotNull();
    }
}
