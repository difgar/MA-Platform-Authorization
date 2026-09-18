package com.mobileamericas.authorization.web.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
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

    /**
     * Descubierto al verificar las probes del Task 10 (docker run + curl),
     * no algo documentado en el spec: aunque management corre en su propio
     * puerto y en su propio contexto hijo, Spring Boot resuelve
     * springSecurityFilterChain (visible por herencia desde el contexto
     * padre) para las peticiones que llegan por ESE puerto también, así que
     * sin esta cadena aparte, /actuator/health/{liveness,readiness} exige el
     * mismo Bearer que el resto de la API. Eso deja las probes de
     * kubernetes/deployment.yaml sin poder autenticarse nunca: el pod jamás
     * pasaría readinessProbe/livenessProbe. @Order(0) para que
     * FilterChainProxy la evalúe antes que filterChain() de más abajo.
     *
     * EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class), NO
     * EndpointRequest.toAnyEndpoint(): la primera versión de esta cadena
     * abría lo que fuera que management.endpoints.web.exposure.include
     * dijera en cada momento, así que la única barrera real entre
     * /actuator/env (o /actuator/beans, /actuator/threaddump...) y quien sea
     * que tenga acceso de red al puerto de management era esa lista en
     * application.yml — un guardia cuya protección vive en otro fichero es
     * peor que ningún guardia, porque quien lee este método deja de pensar en
     * ello. Con el matcher fijado a los dos endpoints concretos, añadir 'env'
     * a exposure.include para depurar un incidente NO lo hace público: cae en
     * el anyRequest().authenticated() de filterChain() y sigue exigiendo
     * Bearer. Ver ActuatorSecurityIT, que reproduce justo ese escenario
     * (expone 'env' a propósito y comprueba que sigue devolviendo 401).
     */
    @Bean
    @Order(0)
    SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class))
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable())
                .build();
    }

    /**
     * La cadena del authorization server: /oauth2/**, /.well-known/** y los
     * endpoints OIDC. Sólo cubre lo que declara getEndpointsMatcher(); todo lo
     * demás cae en la cadena de cierre de más abajo.
     *
     * .oidc(...) no es opcional: sin él no hay documento de descubrimiento
     * OpenID (/.well-known/openid-configuration) ni end_session_endpoint, que
     * es justo lo que la SPA necesita para cerrar sesión. Ver DescubrimientoIT.
     *
     * Esta cadena NO autentica a nadie: si /oauth2/authorize llega sin sesión,
     * la petición se redirige al login que establece la cadena de cierre. Con
     * una sola cadena declarada, /oauth2/authorize responde 401 con
     * WWW-Authenticate y el flujo no arranca nunca.
     *
     * CSRF ignorado SOLO para este matcher (no deshabilitado en general): el
     * canje del código es un POST de servidor a servidor -o de la SPA con
     * PKCE- que no puede traer token CSRF. La cadena de cierre conserva la
     * protección para todo lo demás.
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerFilterChain(
            HttpSecurity http,
            // Mismo @Qualifier y mismo motivo que en la cadena de cierre.
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors)
            throws Exception {
        var authorizationServer = new OAuth2AuthorizationServerConfigurer();
        var endpoints = authorizationServer.getEndpointsMatcher();

        return http
                .securityMatcher(endpoints)
                .with(authorizationServer, cfg -> cfg.oidc(Customizer.withDefaults()))
                // La SPA canjea el código con POST /oauth2/token desde su propio
                // origen: sin CORS el navegador ni siquiera envía la petición.
                .cors(c -> c.configurationSource(cors))
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpoints))
                .build();
    }

    /**
     * Cierre por defecto: todo lo que no sea actuator ni authorization server
     * exige autenticación.
     *
     * Hoy no hay ningún mecanismo con el que autenticarse, y es lo esperado en
     * este punto del rediseño: la emisión propia de la fase 1 ya no está y el
     * login con Google (oauth2Login) llega después, ampliando esta misma
     * cadena. Mientras tanto, denegar es la respuesta correcta.
     *
     * Ya no se declara STATELESS: el flujo de código de autorización necesita
     * una sesión de servidor entre el login y /oauth2/authorize.
     */
    @Bean
    @Order(2)
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
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .build();
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
