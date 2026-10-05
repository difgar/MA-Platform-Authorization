# MA-Platform-Authorization

Servidor de autorización OAuth 2.1 / OpenID Connect de la plataforma, sobre
**Spring Authorization Server**. La identidad la pone Google (login federado con
**un solo** cliente de Google para todo el servicio); quién puede entrar en cada
panel y con qué permisos lo decide este servicio, contra `auth_user`,
`auth_role` y `auth_permission`.

Cada aplicación (panel) es un **cliente OAuth público** registrado en `auth_app`
y obtiene sus tokens por **Authorization Code + PKCE**. Los consumidores
(APIs) verifican esos tokens con el JWKS, sin llamar de vuelta a este servicio.

Spring Boot 4.1.1, Java 25, arquitectura de puertos y adaptadores. Sin
frameworks web en `domain`/`application` (ver `docs/superpowers/specs/`).

## Arrancar en local

Requiere **PostgreSQL** en `localhost:5432`, base `ma_auth`, usuario y contraseña
`ma_auth`. La base debe estar **vacía** la primera vez: Flyway aborta ante un
esquema no vacío sin tabla de historia, para no correr sobre tablas ajenas.
El esquema lo crea Flyway al arrancar; no hay que ejecutar nada a mano.

> **Si el arranque falla con `Migration checksum mismatch for version 3`**, es
> porque tu base local tiene `V3__oauth.sql` aplicada con una versión anterior
> de su cabecera de comentarios (la fase 2 la corrigió dos veces, y Flyway
> incluye los comentarios en el checksum). No es un problema de datos. Remedio,
> en una base de desarrollo: recrearla vacía
> (`DROP SCHEMA public CASCADE; CREATE SCHEMA public;` con el usuario `ma_auth`)
> y arrancar otra vez. En producción no aplica: `V3` no se ha desplegado nunca.

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
curl -s localhost:18081/authorization-api/.well-known/openid-configuration
```

El perfil `dev` (`src/main/resources/application-dev.yml`) fija:

- La API en `http://localhost:18081/authorization-api` y management en
  `http://localhost:28081` (en los demás perfiles es al revés: 8081 y 18081).
- El emisor local, `http://localhost:18081/authorization-api`.
- Orígenes CORS `http://localhost:3000` y `http://localhost:5173` (el de por
  defecto de Vite, que es el que usa `MA-Platform-UI`).
- La clave de firma de `src/main/resources/dev-keys/active.jwk`.
- Un `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` de relleno, **sólo para que el
  contexto arranque**. Con ellos se puede mirar el documento de descubrimiento,
  pero **no se puede iniciar sesión**: Google rechaza el cliente. Para el flujo
  completo en local hay que exportar los del cliente OAuth Web real, que además
  necesita `http://localhost:18081/authorization-api/login/oauth2/code/google`
  entre sus URI de redirección autorizadas.

Sin `SPRING_PROFILES_ACTIVE=dev`, el perfil por defecto exige
`DB_MA_PLATFORM_URL`, `DB_MA_PLATFORM_USER`, `DB_MA_PLATFORM_PASSWORD`,
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, **`AUTH_ISSUER`** y
**`GOOGLE_REDIRECT_URI`**, y **falla al arrancar si falta alguno**: es
intencional, no un bug — mejor un pod que no arranca que uno que arranca mal
configurado.

Las dos últimas no tienen valor por defecto **a propósito**, y merece explicarse
porque antes sí lo tenían: el default era la URL de producción, así que un
entorno nuevo que las olvidara arrancaba emitiendo tokens con el `iss` de
producción y mandando a Google un `redirect_uri` de producción, **sin que nada
fallara**. Es el único sitio del fichero donde se fallaba abierto. Ahora no
arranca. `JWT_KEY_LOCATIONS` y `CORS_ALLOWED_ORIGINS` sí conservan default.

## Ejecutar las pruebas

```bash
./gradlew test              # unitarias: dominio, casos de uso, capa web — sin Spring, sin BD
./gradlew integrationTest   # la suite completa dos veces: MySQL 8.4 y PostgreSQL 17 (Testcontainers)
./gradlew check             # ambas
```

`integrationTest` necesita un daemon de Docker disponible (Testcontainers).
No hay dependencia de red hacia Google: el proveedor OIDC se simula en el propio
test (`GoogleSimulado`), y las claves de prueba están en el repositorio.

## Endpoints

Todo cuelga del context path `/authorization-api`, salvo `/actuator/**`, que vive
en el puerto de management. La lista viva y autoritativa es el documento de
descubrimiento; esto es lo que hay hoy:

```
Descubrimiento
  GET  /.well-known/openid-configuration   metadatos OIDC  ← empieza por aquí
  GET  /oauth2/jwks                        claves públicas ← lo que consumen las APIs

Flujo de la aplicación (Authorization Code + PKCE)
  GET  /oauth2/authorize                   pide el código (navegación, no fetch)
  POST /oauth2/token                       canjea código + code_verifier ← CORS
  GET  /userinfo                           'sub' con el access token (ver aviso abajo)

Login federado con Google (lo usa el navegador, no la aplicación)
  GET  /oauth2/authorization/google        arranca el login
  GET  /login/oauth2/code/google           vuelta de Google

Logout
  GET  el 'end_session_endpoint' del descubrimiento (hoy /connect/logout)

Management  (puerto de management, no expuesto al exterior)
  /actuator/health/{liveness,readiness}
  /actuator/info
```

> **`/userinfo` devuelve sólo `sub`**, y no es un fallo de configuración. El
> mapeador por defecto de Spring Authorization Server parte de los claims del ID
> token y se queda con los que pide el *scope* del access token: `sub` siempre,
> `email` con el scope `email`, `name`/`picture` con `profile`. El *scope* de
> este servicio es el mínimo (`openid` y nada más), así que **el correo y el
> nombre están en el ID token, no en `/userinfo`**. Es lo que sustituye al
> `GET /v1/auth/me` de la fase 1, junto con el ID token. Lo fija
> `FlujoCompletoIT.el_userinfo_devuelve_claims_con_un_token_emitido`, que llama
> al endpoint con un token emitido de verdad.

Lo que **ya no existe** (era el servicio de la fase 1, con emisión propia y
cookies): `POST /v1/auth/google`, `POST /v1/auth/refresh`, `POST /v1/auth/logout`,
`GET /v1/auth/me` y `GET /.well-known/jwks.json`. El JWKS se sirve ahora en
`/oauth2/jwks`. Tampoco hay cookies `ma_access`/`ma_refresh` ni
`CookieBearerTokenResolver`: el token viaja en la cabecera `Authorization`.

## Integrar una aplicación de navegador (SPA)

El módulo **no** habla con `/v1/auth/...`; hace el flujo estándar:

1. Genera `code_verifier` y `code_challenge` (S256) y navega —no `fetch`— a
   `/oauth2/authorize?response_type=code&client_id=<nombre de la app>&redirect_uri=…&scope=openid&code_challenge=…&code_challenge_method=S256&state=…`.
2. Si no hay sesión SSO, el servicio manda al usuario a Google y vuelve solo.
3. Vuelve a `redirect_uri` con `?code=…&state=…`.
4. La SPA hace `POST /oauth2/token` con `grant_type=authorization_code`, el
   `code`, el `code_verifier` y su `client_id`. **Esta petición es cross-origin**
   (ver «Dar de alta una aplicación nueva»).

Cuatro cosas que ahorran una tarde cada una:

- **El access token va en memoria del módulo.** Nunca en `localStorage` ni en
  `sessionStorage`: ahí lo lee cualquier script que acabe en la página.
- **No hay refresh token.** Los clientes son públicos, y un cliente público no
  recibe refresh token aunque declare el *grant* (verificado). Renovar es
  **volver a pasar por `/oauth2/authorize`**: una redirección, que con la sesión
  SSO viva es instantánea y sin pantalla, pero es una redirección. Si la
  aplicación recarga, el token se pierde y hay que repetir el flujo.
- **El access token dura 2 h por defecto**, y es configurable por cliente en
  `auth_app.access_ttl_seconds`. Bajarlo es una decisión por panel.
- **Cerrar sesión es el `end_session_endpoint`**, no borrar el token de memoria.
  Requiere `id_token_hint` y `client_id`, y el `post_logout_redirect_uri` tiene
  que estar en `auth_app.post_logout_redirect_uris` o se rechaza — es una lista
  blanca, no una sugerencia.

## Configurar un consumidor (resource server)

Un consumidor de servicio a servicio, que recibe `Authorization: Bearer …`, no
necesita escribir código: sólo configuración de Spring Security.

```yaml
spring.security.oauth2.resourceserver.jwt:
  jwk-set-uri: https://auth.mobile-americas.com/authorization-api/oauth2/jwks
  audiences: trafficflow            # sin esto, el aud NO se comprueba
  authorities-claim-name: permissions
  authority-prefix: ""
```

Las cuatro propiedades son necesarias, no sólo la primera:

- **`jwk-set-uri`**: dónde están las claves públicas. (Alternativa:
  `issuer-uri: https://auth.mobile-americas.com/authorization-api`, que descubre
  el JWKS solo y **además valida el `iss`**. Es la opción más estricta; exige que
  el consumidor alcance el documento de descubrimiento al arrancar.)
- **`audiences`**: sin ella, Spring Boot no instala el validador de `aud`, así
  que **un token emitido para otra aplicación se acepta igual**. Ese aislamiento
  entre aplicaciones es lo que este servicio garantiza y lo que prueba
  `FlujoCompletoIT`; una configuración de consumidor sin `audiences` lo anula
  del lado del cliente, en silencio y sin que nada falle.
- **`authorities-claim-name: permissions`** y **`authority-prefix: ""`**: por
  defecto un resource server lee las autoridades del claim `scope`/`scp` con el
  prefijo `SCOPE_`. Los tokens de este servicio llevan los permisos en
  `permissions`, concretos y sin prefijo de aplicación. Sin estas dos,
  `hasAuthority('campanas:editar')` no encuentra nunca esa autoridad, aunque el
  token sea válido y esté bien firmado.

### Lo que trae el token

> **Ésta es la copia canónica del contrato de claims.** Si necesitas la tabla en
> otro documento —de este repositorio o de otro— enlaza aquí en vez de copiarla:
> un enlace que se queda viejo se ve, una tabla desincronizada no. Para la forma
> del sistema, ver [docs/arquitectura.md](docs/arquitectura.md).


Access token:

| claim | qué es |
|---|---|
| `iss` | `https://auth.mobile-americas.com/authorization-api` (fijado, no derivado de la petición) |
| `uid` | **`auth_user.id`: el único identificador que no cambia nunca.** Es el que hay que guardar |
| `sub` | **el email del usuario, en minúsculas** — ver aviso abajo |
| `aud` | el `client_id`, que es el nombre de la aplicación en `auth_app` |
| `email` | el mismo email; es el claim que promete ser una dirección |
| `roles` | nombres de rol del usuario **en esa aplicación** |
| `permissions` | permisos ya expandidos (`usuarios:leer`, …); los comodines nunca viajan |
| `scope` | `openid`, y nada más: los permisos no son *scopes* |

El ID token lleva `uid`, `email` y `apps`, más `name` y `picture` si Google los
da. **No lleva `roles` ni `permissions`**: es un documento de identidad que el
navegador puede guardar y que sobrevive horas a un cambio de rol.

`apps` es la lista de **aplicaciones donde este usuario obtendría un token**,
ordenada por nombre, y existe para el panel que hace de puerta de entrada: el
access token está atado a un `aud` y no puede decir nada de las demás.

```json
"apps": [
  {"name": "admin",       "url": "https://admin.mobile-americas.com"},
  {"name": "trafficflow", "url": "https://traffic.mobile-americas.com"}
]
```

Cada entrada lleva **el destino además del nombre** para que el consumidor no
tenga que mantener su propio mapa nombre→dominio: sería un segundo registro que
debe concordar con `auth_app` sin que nada los compare. `url` se omite si la
fila no la tiene, y una entrada sin `url` no debería pintarse como enlace: un
enlace a ninguna parte parece una avería, no una falta de permiso.

La lista **incluye la aplicación que pide el token**. Para descartarse a sí
mismo, un consumidor debe comparar con **su propio `client_id` configurado**, no
con el nombre escrito a mano: así no queda un solo nombre de aplicación en su
código, y una aplicación nueva aparece en su menú el día que se da de alta, sin
tocar el front. La regla es
«obtendría un token», no «tiene algún rol» — es la misma que aplica
`/oauth2/authorize`, para que un menú construido con este claim nunca pinte un
enlace que al pulsarlo deniegue. **Se emite siempre, aunque venga vacío.**

> ## ⚠️ Para guardar, `uid`. Nunca `sub` ni `email`.
>
> **`sub` es el email, no un identificador opaco.** Es contraintuitivo: por
> contrato `sub` es opaco, y aquí resulta ser una dirección de correo.
>
> La consecuencia es que **`sub` y `email` son mutables**: el día que a alguien
> se le cambie el correo —se casa, la empresa se renombra, se corrige una
> errata— cambian los dos. Un consumidor que haya guardado cualquiera de ellos
> como clave ajena se queda con una referencia que no apunta a nadie, **sin que
> nada falle ni avise**: el token siguiente sigue validando perfectamente, sólo
> que ya es otra persona.
>
> Por eso el token lleva **`uid`**, que es `auth_user.id` y no cambia nunca.
>
> La regla, en una línea: **`email` para mostrar en pantalla, `uid` para
> guardar en tu base de datos.**

## Dar de alta una aplicación nueva

Hacen falta **dos** cosas, y olvidar la segunda es el fallo más caro de
diagnosticar de todo el servicio:

1. **Su fila en `auth_app`**, con `redirect_uris` (la URL de callback de la SPA),
   `post_logout_redirect_uris` y, si quiere otro, `access_ttl_seconds`. Hoy se
   hace por migración; la fase 3 trae el CRUD. El `name` de esa fila **es** el
   `client_id`.
2. **Su origen en `authorization.cors.allowed-origins`**
   (`CORS_ALLOWED_ORIGINS`, ver `var.cors_allowed_origins` en `terraform/variables.tf`).

Por qué la segunda no se puede deducir de la primera: `redirect_uri` gobierna
una **navegación**, y `POST /oauth2/token` es una **llamada cross-origin** desde
la SPA. Si su origen no está en la lista, **el navegador corta la petición antes
de enviarla**: no llega nada al servidor, no se registra nada en ningún log de
este servicio, y el único rastro está en la consola del navegador de quien lo
sufre. El síntoma es «el login se queda a medias» y la causa está en otro sitio.

El validador de orígenes exige al menos dos etiquetas después de un `*`
(`https://*.mobile-americas.com` pasa, `https://*.com` no) y **falla al
arrancar**, no en el primer preflight: una lista mal puesta se ve en el log de
arranque del pod.

## Sesión SSO

La sesión que sostiene el SSO entre paneles vive en la base de datos
(`SPRING_SESSION`, `SPRING_SESSION_ATTRIBUTES`, Spring Session JDBC), no en
memoria del pod. Caduca a las **12 h de inactividad**, deslizante.

Se hizo así para que varias réplicas pudieran compartirla; **pero hoy no se
puede correr más de una réplica, y no por la sesión** — ver «Réplicas», justo
debajo.

**Lo único que borra las filas caducadas** es la tarea programada de Spring
Session (`spring.session.jdbc.cleanup-cron`, por defecto cada minuto). Está
desactivada **sólo** en `src/integrationTest/resources/application.yml`, y esa
desactivación no puede escaparse de las pruebas por esa vía; lo que sí la
escaparía es un `SPRING_SESSION_JDBC_CLEANUP_CRON` en el entorno del despliegue. No lo
pongas.

Esa expiración no la cubre ninguna prueba (12 h no se simulan). Comprobarlo a
mano, contra la base del entorno:

```sql
-- 1. Elegir una sesión viva y quedarse con su SESSION_ID. EXPIRY_TIME va en
--    milisegundos desde epoch (UTC), no es un timestamp.
SELECT SESSION_ID, EXPIRY_TIME FROM SPRING_SESSION;

-- 2. Envejecerla a mano, con el SESSION_ID del paso 1, y esperar poco más de
--    un minuto (el cron por defecto corre en punto de cada minuto).
UPDATE SPRING_SESSION SET EXPIRY_TIME = 0 WHERE SESSION_ID = '<el del paso 1>';

-- 3. Debe devolver 0: la fila se ha ido, y con ella sus atributos
--    (SPRING_SESSION_ATTRIBUTES tiene ON DELETE CASCADE).
SELECT COUNT(*) FROM SPRING_SESSION WHERE EXPIRY_TIME = 0;
```

Si el paso 3 no baja a cero, la limpieza no está corriendo y `SPRING_SESSION`
crece sin límite. (La consulta es la misma en MySQL y en PostgreSQL: el esquema
de esa tabla es común a los dos.)

### `/oauth2/authorize` escribe en la base de datos sin autenticar

Hay que saberlo para operar esto: **una petición anónima a `/oauth2/authorize`
con `Accept: text/html` crea una fila en `SPRING_SESSION` y otra en
`SPRING_SESSION_ATTRIBUTES`, con 12 h de retención**, sin que nadie se haya
autenticado. No es un descuido: el usuario que aún no tiene sesión llega ahí
primero, y la petición se guarda en el request cache para poder volver a ella
después del login —guardar crea sesión, y desde que la sesión se persiste, eso
es una escritura en la base de datos compartida de la plataforma—. Es lo que
hace que el login funcione (`LoginIT` lo prueba), y el guardado está acotado a
ese caso: quien no pide HTML recibe un 401 y no estrena sesión
(`DescubrimientoIT.authorize_sin_sesion_y_sin_pedir_html_no_va_al_login`).

Lo que hay que tener en cuenta:

- **La única contención del crecimiento es el `cleanup-cron`** de Spring Session
  (por defecto cada minuto; ver arriba). Nada más borra filas caducadas, y las
  que se crean sin login caducan igual: a las 12 h.
- **La limitación de tasa está fuera del alcance del spec y tiene que venir del
  ingress.** Este servicio no la implementa: un bucle anónimo contra
  `/oauth2/authorize` con `Accept: text/html` escribe una fila por petición
  durante 12 h. Con el cron corriendo el estado se estabiliza, pero el pico lo
  pone quien llame.

## Réplicas: hoy sólo una, y no es una decisión de capacidad

**El máximo de UNA instancia en Cloud Run (`max_instance_count = 1`, `terraform/servicio.tf`) es load-bearing. No lo subas.** (En GKE era `replicas: 1` y el HPA `min = max = 1`; lo vigila `ReplicaUnicaTest`.)

El motivo: **no hay ningún bean `OAuth2AuthorizationService`**, y Spring Boot
4.1.1 no autoconfigura ninguno (sólo `RegisteredClientRepository`,
`AuthorizationServerSettings` y el `JwtDecoder`). Así que Spring Authorization
Server guarda las autorizaciones en **memoria de la instancia**
(`InMemoryOAuth2AuthorizationService`).

Dos consecuencias que hay que tener escritas:

- **La tabla `oauth2_authorization` está creada y vacía.** `V3__oauth.sql` la
  porta con sus 33 columnas y `MigracionIT` comprueba que el porte es correcto,
  pero **nadie la escribe ni la lee**. No crece, no hay que limpiarla, y no
  sirve para auditar nada. Es esquema por adelantado, no almacenamiento vivo.
- **Un código de autorización emitido por una instancia no se puede canjear en otra.**
  Con dos instancias y sin sesión pegajosa, una fracción de los canjes falla con
  `invalid_grant`, de forma intermitente, y el error no señala a ninguna parte.
  La sesión SSO sobrevive al salto de instancia; el código de autorización no.

### La otra mitad: ese almacén en memoria no purga nunca

No es sólo que no se pueda escalar; es que el almacén **crece sin límite
mientras la instancia vive**. Verificado en el bytecode de
`InMemoryOAuth2AuthorizationService` 7.1.1:

- `initializedAuthorizations` (las autorizaciones a medias, las que tienen
  código pero aún no token) es un `MaxSizeHashMap` **acotado a 100**. Ésa está
  bien.
- `authorizations` (las **completas**, las que llegaron a emitir token) es un
  `ConcurrentHashMap` **sin evicción ninguna**.
- `remove()` sólo lo llaman dos rutas de error
  (`OAuth2AuthorizationCodeRequestAuthenticationProvider` y
  `OAuth2AuthorizationConsentAuthenticationProvider`). **Nada purga por
  caducidad, y el logout tampoco**: cerrar sesión mata la sesión SSO, no la
  entrada del almacén.

Cada canje deja ahí una `OAuth2Authorization` con la `Authentication` entera
dentro —el principal de la sesión, con el ID token de Google y sus claims—, del
orden de unos pocos KB, y no sale nunca. La aritmética es la que cada cual puede
rehacer: sin renovación silenciosa (cliente público, sin refresh token), cada
usuario vuelve a pasar por `/oauth2/authorize` **cada 2 h por aplicación**, así
que son ~12 entradas por usuario y aplicación al día. Con unas decenas de
usuarios y tres paneles, son miles de entradas de varios KB entre despliegue y
despliegue.

La instancia tiene 1 GiB y `-XX:MaxRAMPercentage=50` (unos 512 MB de heap), así que
esto no revienta hoy ni mañana. Y **desde el 2026-10-03 el servicio tiene mínimo 0
instancias**: cada vez que se queda sin uso, Cloud Run apaga la instancia y el mapa se
vacía. Con el tráfico de hoy, esa es la purga. Si algún día se sube el mínimo a 1, el
riesgo vuelve: un OOM semanas después de un despliegue, sin causa aparente, y la sonda
de vida reiniciando la instancia —lo que limpia el mapa y, con él, la evidencia—.

**Qué hacer mientras tanto**, porque el arreglo de verdad es el
`OAuth2AuthorizationService` persistente de más abajo:

- **Vigilar el heap.** `jvm.memory.used` no se sirve hoy: `exposure.include` es
  `health,info`. Para mirarlo hay que añadir `metrics` a esa lista (no lo hace
  público: la cadena de actuator sólo abre sin autenticar `health` e `info`), o
  mirar la memoria del contenedor en Cloud Run.
- **Con mínimo 1, reiniciar la instancia de vez en cuando** si pasan semanas sin
  desplegar (una revisión nueva basta): es la única purga. Corta los canjes en vuelo
  (unos segundos), no las sesiones SSO, que están en la base de datos. Con mínimo 0
  lo hace Cloud Run solo.

**Qué haría falta para poder escalar:** declarar un
`JdbcOAuth2AuthorizationService`. **Se intentó en la fase 2 y se abortó**, y
conviene saber contra qué se choca antes de volver a intentarlo: esa clase
serializa la `Authentication` completa a la columna `attributes` y, al releerla,
la deserializa con el validador de tipos polimórficos de Spring Security, que
sólo admite clases de su propia lista. Nuestro principal es
`UsuarioOidcService.UsuarioAutenticado`, así que la lectura falla con
`Could not resolve type id '…UsuarioAutenticado' … PolymorphicTypeValidator
denied resolution` y `POST /oauth2/token` responde 500. Escribir sí escribe; lo
que no se puede es volver a leer. Arreglarlo exige un mixin de Jackson propio
para ese tipo y ampliar el validador —que es la defensa contra deserialización
polimórfica insegura—, y eso es un trabajo con su propio diseño y sus propias
pruebas, no un `@Bean`.

## Qué ve quien no puede entrar

Una persona que se autentica en Google pero **no está dada de alta** —o está de
baja, o Google no da su email como verificado— **vuelve a la aplicación desde la
que vino**, con el motivo en la URL:

```
https://admin.mobile-americas.com/callback?error=access_denied&error_reason=usuario_no_registrado&state=...
```

Dos códigos, en capas:

| parámetro | qué lleva |
|---|---|
| `error` | siempre `access_denied`, que es **estándar de OAuth 2.0**: un cliente genérico que no conozca nada de esta plataforma se comporta bien |
| `error_reason` | el motivo concreto — **los siete, en la tabla de abajo** |

Un consumidor traduce por `error_reason` cuando lo reconoce y **cae al mensaje
de `access_denied` cuando no**, así que un motivo nuevo nunca llega crudo a una
pantalla y esta lista se puede ampliar sin coordinar con nadie.

### Los siete motivos que emite este servicio

Ésta es la lista completa: **no hay más, y no están enumerados en ningún otro
sitio de este documento**. Si añades uno, se añade aquí.

| `error_reason` | dónde se rechaza | qué pasó | qué puede hacer la persona |
|---|---|---|---|
| `usuario_no_registrado` | login | la identidad es válida pero no está dada de alta | pedir acceso a un administrador |
| `usuario_inactivo` | login | está dada de alta y **desactivada** | reclamar la baja a un administrador |
| `email_no_verificado` | login | Google no da el correo como verificado | **verificarlo él mismo** en su cuenta de Google |
| `email_ausente` | login | Google no entregó el correo | reintentar; depende del consentimiento que diera |
| `sin_rol` | `/oauth2/authorize` | no tiene **ningún rol en esa aplicación** | pedir acceso **a esa aplicación** |
| `access_denied` | login | **Google no completó**: la persona canceló | reintentar |
| `login_fallido` | login | cualquier otro fallo, resumido sin detalle a propósito | reintentar |

> **Ojo con `access_denied` y `sin_rol`: llegan los dos con `error=access_denied`
> y no significan lo mismo.** El primero es «canceló»; el segundo, «no tiene
> permiso aquí». Confundirlos manda a *pedir un permiso a quien ya lo tiene*.
>
> **`sin_rol` cierra además la sesión de auth** de esa cuenta: el siguiente
> `/oauth2/authorize` vuelve a Google, que siempre muestra el selector de cuentas
> (`prompt=select_account`). Sin eso, quien fue rechazado quedaba atrapado con la
> misma cuenta —cada reintento repetía el rechazo sin pasar por Google, y el
> logout OIDC daba 400 por no haber `id_token`—. Un consumidor no tiene que
> cerrar nada: basta con ofrecer «entrar con otra cuenta» como un login normal.
> Coste: si esa misma cuenta tenía sesión abierta en OTRA aplicación, su próximo
> `/authorize` también pasará por Google.
>
> Y **la ausencia de `error_reason` no significa nada**, a propósito: un hueco lo
> produce cualquiera —una caída de red, una respuesta a medias, un consumidor
> que aún no conoce el contrato— y si un significado viajara ahí, todos esos
> casos lo heredarían. Por eso `sin_rol` es explícito y no se deduce del
> silencio. Ante un `error_reason` desconocido o ausente: **mensaje genérico**,
> nunca una afirmación sobre permisos.
>
> Un consumidor puede añadir motivos **propios** para lo que le pase a él —una
> avería de red suya, por ejemplo— siempre que no reutilice estos siete. Los
> suyos los define él; éstos, este documento.

**El `redirect_uri` se valida contra `auth_app`**, igual que en `/authorize` y
en el logout. Sin esa comprobación esto sería un *redirect abierto* servido por
la pantalla que el usuario acaba de reconocer como fiable.

**Queda un JSON con 401 para cuando no hay a dónde volver**: quien llega al
callback de Google directamente, con la sesión caducada, o pidiendo un
`client_id` que ya no está registrado. Ahí no hay `redirect_uri` que valga y
adivinar una sería peor.

> **Por qué se distingue «no estás dado de alta» de «estás dado de baja».**
> Parece enumeración de cuentas y casi no lo es: sólo se lo cuenta a quien **ya
> ha completado el login en Google con esa identidad**, así que para preguntar
> por un correo ajeno habría que controlar esa cuenta. A cambio, la persona sabe
> si tiene que **pedir acceso** o **reclamar una baja**, que son acciones
> distintas. El `error` estándar no distingue; el detalle vive sólo en
> `error_reason`.

## Despliegue

**Cloud Run desde el 2026-10-03** (antes, GKE; el diseño del cambio está en
`docs/superpowers/specs/2026-10-03-auth-en-cloud-run-design.md`). Tres sitios:

| Dónde | Qué |
|---|---|
| `terraform/` | Lo propio del auth en `sms-ma-platform`, con su state (`gs://ma-platform-auth-tfstate`): el Cloud Run `ma-authorization`, su cuenta de servicio, los contenedores de sus secretos, el registro de imágenes, el build y el NEG + backend del LB |
| `shared/` | Lo compartido, a mano y sólo añadiendo: la base `ma_auth`, los valores de los secretos, los usuarios iniciales y la regla del url-map. **Ningún terraform toca la base ni el LB**: los comparten tres proyectos |
| `scripts/construir-imagen.sh` | Construye la imagen en Cloud Build (`cloudbuild.yaml` solo construye) y la fija **por digest** en `terraform/imagenes.auto.tfvars` |

Desplegar una versión: suite completa en local → commit → `scripts/construir-imagen.sh`
→ `terraform -chdir=terraform plan -out=tfplan` → `apply tfplan`. Con
`export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token --account=it.mobile.americas@gmail.com)"`,
porque las ADC de la máquina impersonan otra cuenta. No hay trigger: el de GKE
(`ma-authorization-trigger`) se borró.

Puntos que importa no olvidar:

- **Como mucho una instancia** (Cloud Run mín 0 y máx 1; mín 0 desde el 2026-10-03: el primer login tras un rato parado espera ~15–20 s). Ver «Réplicas»; lo vigila
  `ReplicaUnicaTest` leyendo `terraform/servicio.tf`.
- **El emisor se fija a mano** (`AUTH_ISSUER`, `var.issuer` en `terraform/variables.tf`).
  Sin él, Spring Authorization Server lo deriva de la petición entrante, y detrás del
  LB eso sería la URL `run.app`: los tokens saldrían con un `iss` que ningún
  consumidor acepta. Incluye el context path. Lo vigila `EmisorDeProduccionTest`.
- **El `redirect_uri` de Google se declara literal** (`GOOGLE_REDIRECT_URI`,
  `"${var.issuer}/login/oauth2/code/google"`). Tiene que ser **carácter a carácter** la
  misma URL registrada en la consola de Google Cloud; si no, `redirect_uri_mismatch` y el
  login cae entero.
- **Cabeceras reenviadas.** La aplicación respeta `X-Forwarded-*`
  (`server.forward-headers-strategy: framework`). Con `AUTH_ISSUER` y
  `GOOGLE_REDIRECT_URI` fijados, los dos valores críticos no dependen de ellas; el resto
  de URL derivadas sí. Comprobado el 2026-10-03: el documento de descubrimiento sale
  entero en `https://auth.mobile-americas.com/authorization-api/...`.
- **UTC**: `TZ=UTC` y `-Duser.timezone=UTC` en `JAVA_TOOL_OPTIONS`. Los `TIMESTAMP(6)`
  del esquema no llevan zona (ver la cabecera de `V3__oauth.sql`).
- **Nada debe sobrescribir `SPRING_FLYWAY_LOCATIONS`** con un solo valor: con una sola
  ubicación no se aplicaría `V4` y el servicio arrancaría bien **hasta el primer login**.
- **La base** es `ma_auth` en la PostgreSQL compartida `ma-platform-db-pgsql`, por el
  conector de Cloud SQL (la instancia lo exige). Se creó **nueva y vacía**
  (`shared/db/crear-base.sh`) y Flyway la llenó al primer arranque. **No usar
  `spring.flyway.baseline-on-migrate: true`**: saltaría `V1` en silencio. Pool de 3: la
  instancia tiene 50 conexiones para tres proyectos; cada una se ve como
  `ma-platform-auth/<revisión>` en `pg_stat_activity`.
- **Secretos** en Secret Manager de `sms-ma-platform`; terraform crea los contenedores y
  `shared/` carga los valores, que nunca pasan por el state:
  `ma-auth-google-client-{id,secret}` (un solo cliente OAuth para todo el servicio),
  `ma-auth-jwk` (montada como fichero en `/etc/ma-auth/keys/active.jwk`) y
  `ma-auth-db-{user,password}`.
- `cloudbuild.yaml` **no ejecuta tests** (Testcontainers necesitaría Docker dentro de
  Docker). La suite completa se ejecuta en local antes de construir.

### Pasos manuales, fuera de los commits

Hechos el 2026-10-03; quedan escritos por si hay que repetirlos (otro entorno, desastre):

1. **El cliente OAuth Web de Google** (`sms-ma-platform`), con
   `https://auth.mobile-americas.com/authorization-api/login/oauth2/code/google` entre sus
   URI de redirección. Pantalla de consentimiento **externa**; mientras esté en «Prueba»,
   cada usuario nuevo de la plataforma tiene que estar también en «Usuarios de prueba»
   (máx. 100), o hay que publicar la app.
2. `shared/db/crear-base.sh` → `terraform apply` (primera parte) →
   `shared/secretos/cargar.sh` → imagen → `terraform apply` → url-map
   (`shared/README.md`) → `shared/db/usuarios.sql`.
3. **Revisar el TTL por cliente**: 2 h por defecto.

## Generar una clave de firma

Las claves son JWK RSA con `kid`, generadas con `nimbus-jose-jwt`
(`RSAKeyGenerator`, ya en el classpath del proyecto). Ejemplo mínimo:

```java
RSAKey clave = new RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .keyID("prod-2026-09")   // cambia con cada rotación
        .generate();
System.out.println(clave.toJSONString());
```

El JSON resultante es el contenido completo del fichero (incluida la parte
privada: `d`, `p`, `q`...). En cualquier entorno que no sea `dev`, ese fichero
**no se commitea**: va a Secret Manager (`ma-auth-jwk`, `shared/secretos/cargar.sh`) y
Cloud Run lo monta como fichero, nunca como variable de entorno ni en el código.
`authorization.jwt.key-locations` admite varias claves: durante una rotación se
declaran dos, y la primera es la que firma.

`src/main/resources/dev-keys/active.jwk` es la única excepción, y sólo porque es
de desarrollo puro: no protege nada real, nunca sale del perfil `dev`, `bootJar`
la excluye del artefacto y en cualquier otro perfil `JWT_KEY_LOCATIONS` la
sustituye por la ruta del Secret montado en el pod.
