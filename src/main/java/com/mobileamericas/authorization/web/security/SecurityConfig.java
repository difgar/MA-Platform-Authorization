package com.mobileamericas.authorization.web.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
@EnableConfigurationProperties(CorsProperties.class)
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
                // Sin CSRF porque no hay sesión de servidor y ninguna escritura es
                // un GET. El access token se acepta tanto por cabecera Authorization
                // (servicio a servicio) como por la cookie ma_access
                // (CookieBearerTokenResolver, para el navegador). Aceptar la cookie
                // reabre en principio la superficie CSRF que motivó esta decisión;
                // lo que la cierra de verdad es SameSite=Lax en esa cookie
                // (CookieFactory): un POST cross-site no la envía, así que un
                // formulario ajeno no puede autenticarse con ella. SameSite=Lax deja
                // de ser un detalle cosmético en el momento en que la cookie se
                // acepta como credencial: es el control que sostiene toda esta
                // decisión.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.POST,
                                "/v1/auth/google", "/v1/auth/refresh", "/v1/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers("/error").permitAll()
                        // Denegar por defecto. Antes: .anyRequest().permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o
                        .bearerTokenResolver(new CookieBearerTokenResolver())
                        .jwt(j -> j.jwtAuthenticationConverter(conversor())))
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
     * Las patrones (no una lista de orígenes exactos) porque el spec quiere
     * admitir formas como https://*.mobile-americas.com.
     *
     * OJO con lo que de verdad protege esto: CorsConfiguration.validateAllowCredentials()
     * (spring-web) solo revisa allowedOrigins; NUNCA mira allowedOriginPatterns,
     * así que setAllowedOriginPatterns(List.of("*")) con allowCredentials(true)
     * NO falla al arrancar aunque sea exactamente el mismo agujero que esa
     * validación existe para evitar: reflejar el Origin de cualquier llamador
     * con Access-Control-Allow-Credentials: true. Por eso el '*' se rechaza
     * aquí a mano, explícitamente, en vez de confiar en que Spring lo haga.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties props) {
        var origenes = props.allowedOrigins();
        if (origenes.contains("*")) {
            throw new IllegalStateException(
                    "authorization.cors.allowed-origins no admite '*': con "
                            + "allowCredentials(true) reflejaría el Origin de cualquier "
                            + "llamador. Usa un patrón concreto, p.ej. "
                            + "https://*.mobile-americas.com.");
        }

        var c = new CorsConfiguration();
        c.setAllowedOriginPatterns(origenes);
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        c.setAllowedHeaders(List.of("Content-Type", "Accept", "Origin", "X-Requested-With"));
        c.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", c);
        return source;
    }
}
