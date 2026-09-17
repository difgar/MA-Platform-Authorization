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
     * con Access-Control-Allow-Credentials: true. Por eso el comodín se valida
     * aquí a mano, explícitamente, en vez de confiar en que Spring lo haga.
     *
     * Rechazar solo el string exacto '*' no basta: https://* es el mismo
     * agujero con otro texto (coincide con cualquier origen https), y
     * https://*.com casi lo mismo (coincide con cualquier origen de ese TLD).
     * La regla real es sobre la POSICIÓN del comodín, no sobre su forma
     * literal: validarOrigenes() exige al menos dos etiquetas después de un
     * '*', así que https://*.mobile-americas.com pasa y https://*.com no.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties props) {
        var origenes = props.allowedOrigins();
        validarOrigenes(origenes);

        var c = new CorsConfiguration();
        c.setAllowedOriginPatterns(origenes);
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        c.setAllowedHeaders(List.of("Content-Type", "Accept", "Origin", "X-Requested-With"));
        c.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", c);
        return source;
    }

    /**
     * Exige al menos dos etiquetas (separadas por punto) después del último
     * '*' de cada origen, si lo tiene. Un origen sin comodín pasa siempre: es
     * exacto, no un patrón que pueda abarcar de más.
     *
     * Dos etiquetas es una línea elegida a propósito, no un descuido: cubre
     * el caso real de este servicio (subdominios bajo un dominio propio,
     * https://*.mobile-americas.com) sin dejar pasar un comodín a nivel de
     * TLD (https://*.com, que coincidiría con cualquier origen de ese TLD).
     * NO persigue dominios de segundo nivel públicos como .co.uk
     * (https://*.co.uk se aceptaría con esta regla): hacerlo bien exigiría
     * una lista de sufijos públicos, desproporcionado para un servicio
     * interno con un puñado de orígenes conocidos de antemano.
     *
     * Falla al arrancar, no en el primer preflight: una configuración mala se
     * ve en el log de arranque, no como un CORS roto en producción reportado
     * por un cliente.
     */
    private static void validarOrigenes(List<String> origenes) {
        for (var origen : origenes) {
            var comodin = origen.lastIndexOf('*');
            if (comodin < 0) {
                continue;
            }
            var sufijo = origen.substring(comodin + 1).replaceFirst(":\\d+$", "");
            var etiquetas = java.util.Arrays.stream(sufijo.split("\\."))
                    .filter(s -> !s.isBlank())
                    .count();
            if (etiquetas < 2) {
                throw new IllegalStateException(
                        "authorization.cors.allowed-origins rechaza '" + origen + "': un "
                                + "comodín necesita al menos dos etiquetas después de él "
                                + "(p.ej. https://*.mobile-americas.com), o abarca demasiados "
                                + "orígenes distintos con Access-Control-Allow-Credentials: "
                                + "true. Un comodín con una sola etiqueta detrás (o ninguna, "
                                + "como '*' o 'https://*') coincide con cualquier origen de "
                                + "ese TLD o esquema.");
            }
        }
    }
}
