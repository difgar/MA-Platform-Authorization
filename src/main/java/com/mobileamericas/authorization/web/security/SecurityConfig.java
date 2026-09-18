package com.mobileamericas.authorization.web.security;

import com.mobileamericas.authorization.adapter.google.UsuarioOidcService;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(CorsProperties.class)
class SecurityConfig {

    /**
     * text/html de verdad, y no "text/html o cualquier cosa".
     *
     * MediaTypeRequestMatcher no ignora ningún tipo por defecto, y un Accept
     * ausente -o el comodín que manda curl- se resuelve como MediaType.ALL,
     * que isCompatibleWith(text/html) da por bueno. Sin ignorarlo, una
     * petición de máquina a /oauth2/token, /oauth2/introspect o /oauth2/revoke
     * que caiga en el anyRequest().authenticated() de esa cadena -por ejemplo
     * sin credenciales de cliente- recibe un 302 hacia Google y, de paso, una
     * cookie de sesión, en vez de un error de OAuth: el cliente no sabe qué
     * hacer con eso y el diagnóstico apunta al sitio equivocado.
     *
     * Con MediaType.ALL ignorado, esas peticiones vuelven al 401 del
     * HttpStatusEntryPoint que registra el configurer, y el navegador -que
     * manda 'text/html,application/xhtml+xml,...'- sigue yendo al login.
     * DescubrimientoIT tiene una prueba por rama.
     */
    private static final MediaTypeRequestMatcher NAVEGADOR = navegador();

    private static MediaTypeRequestMatcher navegador() {
        var matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        matcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
        return matcher;
    }

    /**
     * Descubierto al verificar las probes del Task 10 (docker run + curl),
     * no algo documentado en el spec: aunque management corre en su propio
     * puerto y en su propio contexto hijo, Spring Boot resuelve
     * springSecurityFilterChain (visible por herencia desde el contexto
     * padre) para las peticiones que llegan por ESE puerto también, así que
     * sin esta cadena aparte, /actuator/health/{liveness,readiness} exige lo
     * mismo que el resto de la API: hoy, una sesión establecida con Google.
     * Eso deja las probes de kubernetes/deployment.yaml sin poder autenticarse
     * nunca -una probe no hace un login federado-: el pod jamás pasaría
     * readinessProbe/livenessProbe. @Order(0) para que FilterChainProxy la
     * evalúe antes que filterChain() de más abajo.
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
     * el anyRequest().authenticated() de filterChain(), que hoy responde con
     * la redirección al login con Google (antes, con la emisión propia de la
     * fase 1, era un 401 con WWW-Authenticate: Bearer). Ver
     * ActuatorSecurityIT, que reproduce justo ese escenario: expone 'env' a
     * propósito y comprueba que no sale un 200 con el entorno del proceso
     * dentro, sea cual sea el rechazo que toque.
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
     * Esta cadena NO autentica a nadie: no declara ningún mecanismo. Lo que sí
     * hace es DENEGAR, y de eso se encarga el anyRequest().authenticated() de
     * más abajo, que no es decorativo ni lo añade el framework por su cuenta:
     * init() del configurer no llama a authorizeHttpRequests.
     *
     * Sin esa línea, una petición anónima y bien formada a /oauth2/authorize
     * NO se deniega: el proveedor no encuentra principal y el filtro del
     * endpoint devuelve al navegador a la aplicación que lo mandó con
     * 302 ...?error=invalid_request&error_description=OAuth 2.0 Parameter:
     * principal (comprobado, no deducido). Es decir, el usuario que aún no ha
     * iniciado sesión no acaba en un login: acaba de vuelta en su aplicación
     * con un error que parece culpa suya. Con la línea, la misma petición da
     * 401, que es el punto donde engancha el login.
     *
     * Ese 401 lo pone el HttpStatusEntryPoint(UNAUTHORIZED) que el propio
     * configurer registra; al ser el único entry point mapeado, Spring
     * Security lo usaría para toda esta cadena. Y con eso solo, el usuario sin
     * sesión recibe 401 con WWW-Authenticate: Bearer -como si le faltara un
     * token- en vez de ir a autenticarse, porque el redirect al login no puede
     * venir de la cadena de cierre: las dos son disjuntas por securityMatcher,
     * así que la de cierre nunca ve /oauth2/authorize. De ahí el
     * exceptionHandling de abajo, que es lo que convierte ese 401 en un viaje
     * a Google.
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
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors,
            AccesoAlClienteValidator validador)
            throws Exception {
        var authorizationServer = new OAuth2AuthorizationServerConfigurer();
        var endpoints = authorizationServer.getEndpointsMatcher();

        return http
                .securityMatcher(endpoints)
                .with(authorizationServer, cfg -> {
                    cfg.oidc(Customizer.withDefaults());
                    // Sustituye al validador por defecto del proveedor, no se
                    // suma a él: AccesoAlClienteValidator delega en ese
                    // validador de serie como primer paso, así que la
                    // validación de redirect_uri y scope no se pierde, sólo
                    // se amplía con el rechazo por falta de roles. PKCE
                    // (code_challenge) y grant_type no dependen de esta
                    // sustitución: el framework los aplica alrededor, fuera
                    // del hueco que ocupa este validador.
                    cfg.authorizationEndpoint(a -> a.authenticationProviders(ps -> ps.forEach(p -> {
                        if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider prov) {
                            prov.setAuthenticationValidator(validador);
                        }
                    })));
                })
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                // La SPA canjea el código con POST /oauth2/token desde su propio
                // origen: sin CORS el navegador ni siquiera envía la petición.
                .cors(c -> c.configurationSource(cors))
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpoints))
                // Esta cadena NO autentica: depende de la sesión que establezca
                // la de cierre. Lo único que hace aquí es, cuando no hay
                // sesión, mandar al usuario a por ella en lugar de responder
                // 401 con WWW-Authenticate: Bearer.
                //
                // Acotado a text/html porque el único endpoint de esta cadena
                // al que se llega sin sesión y navegando es /oauth2/authorize;
                // los demás los llama código, que no sabría qué hacer con una
                // redirección a una pantalla de login.
                //
                // La URL es la del filtro de oauth2Login de la cadena de
                // cierre, no una pantalla propia: con un solo proveedor
                // registrado Spring redirige directo a Google sin pantalla de
                // selección, y auth no sirve HTML.
                .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/google"),
                        NAVEGADOR))
                // El mismo matcher gobierna las dos mitades de la misma idea,
                // y no es una coincidencia: la petición guardada existe SÓLO
                // para volver a ella después del login, así que se guarda
                // exactamente cuando se manda a alguien al login.
                //
                // ExceptionTranslationFilter llama a saveRequest() antes del
                // entry point, y guardar crea sesión; desde que la sesión se
                // persiste, eso es una fila en SPRING_SESSION con 12 h de
                // vida. Con el matcher, el navegador la estrena -la necesita- y
                // el cliente de máquina que recibe el 401 no. Ver
                // DescubrimientoIT.authorize_sin_sesion_y_sin_pedir_html_no_va_al_login,
                // que afirma también que no hay Set-Cookie.
                .requestCache(c -> c.requestCache(cacheAcotadoA(NAVEGADOR)))
                .build();
    }

    /**
     * Tarea 7: sin esto, un usuario sin ningún rol en la app que pide el
     * token pasa igual por /oauth2/authorize y recibe un código -y luego un
     * token con cero autoridades-, que es peor que un rechazo: la aplicación
     * cree que el usuario ha entrado y no puede hacer nada. Ver
     * AccesoAlClienteValidator, que delega primero en el validador de serie
     * (redirect_uri, scope) antes de mirar los roles -PKCE y grant_type los
     * aplica el framework por fuera, no esta delegación-, y que se enchufa
     * más arriba dentro de authorizationServerFilterChain.
     */
    @Bean
    AccesoAlClienteValidator accesoAlClienteValidator(UserRepository usuarios, AppRepository apps) {
        return new AccesoAlClienteValidator(usuarios, apps);
    }

    /**
     * Un request cache que sólo GUARDA lo que case con el matcher.
     *
     * Ese matcher no gobierna la recuperación: getRequest() sigue devolviendo
     * lo que haya guardado cualquier cadena sobre la misma sesión (verificado,
     * ver LoginIT.sin_sesion_authorize_manda_al_login_y_al_volver_emite_el_codigo:
     * guarda la cadena @Order(1) y lo recupera el manejador de éxito de
     * oauth2Login, que vive en la @Order(2)). Por eso se acota el guardado en
     * vez de desactivar el cache con un NullRequestCache, que rompería esa
     * vuelta.
     */
    private static RequestCache cacheAcotadoA(RequestMatcher aGuardar) {
        var cache = new HttpSessionRequestCache();
        cache.setRequestMatcher(aGuardar);
        return cache;
    }

    /**
     * Cierre por defecto: todo lo que no sea actuator ni authorization server
     * exige autenticación, y es ESTA cadena la que sabe autenticar.
     *
     * El mecanismo es el login federado: nada de contraseñas propias, la
     * identidad la da Google y quién puede entrar lo decide
     * UsuarioOidcService. Como sólo hay un proveedor registrado, Spring no
     * genera pantalla de selección y redirige directo a él -auth no sirve
     * HTML-, y esa misma URL (/oauth2/authorization/google) es la que usa el
     * entry point de la cadena del authorization server.
     *
     * No se declaran rutas de actuator aquí: la cadena @Order(0) ya cubre
     * health e info, y lo hace por tipo de endpoint en vez de por ruta, así
     * que sobrevive a un cambio de management.endpoints.web.base-path.
     *
     * Ya no se declara STATELESS: el flujo de código de autorización necesita
     * una sesión de servidor entre el login y /oauth2/authorize. Esa sesión se
     * guarda en SPRING_SESSION (spring-session-jdbc, ver application.yml) y no
     * en memoria del pod: con varias réplicas y sin sesión pegajosa, una
     * sesión en memoria obliga a pasar otra vez por Google en cada pod.
     */
    @Bean
    @Order(2)
    SecurityFilterChain filterChain(
            HttpSecurity http,
            // Spring MVC también expone HandlerMappingIntrospector como
            // CorsConfigurationSource (para resolver @CrossOrigin por ruta), así
            // que sin este @Qualifier la inyección es ambigua entre ese bean y
            // el nuestro: NoUniqueBeanDefinitionException al arrancar.
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors,
            UsuarioOidcService usuarios)
            throws Exception {
        return http
                .cors(c -> c.configurationSource(cors))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(o -> o
                        .userInfoEndpoint(u -> u
                                .oidcUserService(usuarios)
                                // Sin este mapper no se emite ningún ID token:
                                // el generador exige un factor de autenticación
                                // que el login OIDC no sella por su cuenta. Ver
                                // SelloDelFactorDeAutenticacion.
                                .userAuthoritiesMapper(new SelloDelFactorDeAutenticacion()))
                        // Sin este handler el fallo se redirige a /login?error
                        // y el motivo del rechazo no viaja en ese 302: quien
                        // intenta entrar no puede saber por qué no puede. Ver
                        // RespuestaDeLoginFallido.
                        .failureHandler(new RespuestaDeLoginFallido()))
                // Esta cadena no guarda NINGUNA petición: la única a la que
                // hay que volver después del login es la de /oauth2/authorize,
                // y ésa la guarda la cadena @Order(1). Guardar aquí sólo
                // conseguiría que un GET anónimo a cualquier ruta estrenara
                // una sesión persistida de 12 h en la base de datos compartida
                // de la plataforma, sin nada a lo que volver: este servicio no
                // sirve contenido. Ver
                // LoginIT.una_peticion_anonima_no_escribe_sesion_en_la_base_de_datos.
                .requestCache(c -> c.requestCache(cacheAcotadoA(peticion -> false)))
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
