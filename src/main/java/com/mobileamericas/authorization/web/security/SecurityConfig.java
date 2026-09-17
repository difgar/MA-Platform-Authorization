package com.mobileamericas.authorization.web.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(
            HttpSecurity http,
            // Spring MVC también expone HandlerMappingIntrospector como
            // CorsConfigurationSource (para resolver @CrossOrigin por ruta), así
            // que sin este @Qualifier la inyección es ambigua entre ese bean y
            // el nuestro: NoUniqueBeanDefinitionException al arrancar.
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors)
            throws Exception {
        return http
                .cors(c -> c.configurationSource(cors))
                // Sin CSRF porque no hay sesión de servidor y el token va en una
                // cookie SameSite=Lax; ninguna escritura es un GET.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.POST,
                                "/v1/auth/google", "/v1/auth/refresh", "/v1/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers("/error").permitAll()
                        // Denegar por defecto. Antes: .anyRequest().permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(j -> j
                        .jwtAuthenticationConverter(conversor())))
                .build();
    }

    /**
     * Las autoridades salen del claim 'permissions' tal cual, sin prefijo.
     *
     * Por defecto, un resource server de Spring Security lee las autoridades
     * del claim 'scope'/'scp' con el prefijo 'SCOPE_'. Sin este conversor,
     * hasAuthority('usuarios:editar') no encontraría nunca esa autoridad,
     * porque nuestros tokens no llevan 'scope' y las autoridades reales viven
     * en 'permissions' sin prefijo. Los consumidores de este servicio logran
     * el mismo efecto por propiedades:
     * spring.security.oauth2.resourceserver.jwt.authorities-claim-name=permissions
     * spring.security.oauth2.resourceserver.jwt.authority-prefix=
     */
    private static JwtAuthenticationConverter conversor() {
        var autoridades = new JwtGrantedAuthoritiesConverter();
        autoridades.setAuthorityPrefix("");
        autoridades.setAuthoritiesClaimName("permissions");

        var conversor = new JwtAuthenticationConverter();
        conversor.setJwtGrantedAuthoritiesConverter(autoridades);
        return conversor;
    }

    /**
     * authorization.cors.allowed-origins debe ser un escalar separado por comas
     * (p.ej. "https://a,https://b"), no una secuencia YAML con guiones: una
     * secuencia se aplana en claves indexadas (allowed-origins[0], [1]...) y
     * ${authorization.cors.allowed-origins}, sin índice, no resolvería.
     * El conversor de Spring convierte ese escalar a List<String> por la coma.
     * De paso encaja con cómo se pasa en Kubernetes, como una única variable
     * de entorno.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${authorization.cors.allowed-origins}") List<String> origenes) {
        var c = new CorsConfiguration();
        // Lista explícita, nunca '*': con allowCredentials el comodín no es válido
        // y además abriría el servicio a cualquier origen.
        c.setAllowedOriginPatterns(origenes);
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        c.setAllowedHeaders(List.of("Content-Type", "Accept", "Origin", "X-Requested-With"));
        c.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", c);
        return source;
    }
}
