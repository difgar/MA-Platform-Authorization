# Rediseño de la emisión de tokens sobre Spring Authorization Server

**Fecha:** 2026-09-18
**Sustituye a:** la §5 (Tokens) de `2026-09-16-reescritura-autorizacion-design.md`
**Estado:** diseño aprobado, validado con prueba de concepto, pendiente de plan

---

## 1. Por qué, si la fase 1 acaba de terminar

La fase 1 entregó un servicio que funciona y está probado. Lo que no hizo fue
preguntar por la **topología del cliente**, y ahí está el hueco.

La topología real es: un *home* y varios módulos en **subdominios hermanos**,
cada uno con su bucket, su proyecto y su despliegue independiente. Sobre eso, el
diseño de la fase 1 se rompe en un punto concreto:

> El access token se entrega **solo en una cookie `HttpOnly`** y el cuerpo va
> vacío, para que ningún XSS lo lea. Pero el módulo de TrafficFlow llama a **su
> propia API**, que está en otro host. La cookie no llega ahí, y el JavaScript
> del módulo **no puede leerla** para ponerla en una cabecera.

Las dos salidas obvias son malas. Una cookie en el dominio padre convierte
**todos los subdominios en una única frontera de seguridad**: un XSS en cualquier
módulo puede actuar como el usuario contra todos los demás. Un token compartido
entre módulos es peor todavía, porque las autoridades no están cualificadas por
aplicación — ya está documentado en el spec anterior que un token de `fgf`
satisfaría `usuarios:borrar` en el API de administración.

La separación correcta, y es la frase que lo ordena todo:

> **SSO es sesión compartida, no token compartido.**

Cada aplicación es un cliente OAuth independiente y recibe **su propio token**,
con su propia audiencia y sus propios permisos. El usuario percibe una sesión
única porque la sesión SSO vive en auth; técnicamente cada módulo tiene una
credencial distinta y limitada a lo suyo.

### 1.1 Y por qué Spring Authorization Server, si el spec anterior lo descartó

El spec de la fase 1 lo descartó explícitamente por «desproporcionado para dos
SPAs internas». Con dos aplicaciones era razonable. Dejó de serlo por dos hechos:

1. **Lo que pide esta topología es un proveedor OIDC.** *Authorization Code* con
   PKCE, un cliente por aplicación, sesión SSO, token por audiencia y logout
   iniciado por el cliente no es «auth con dos endpoints más»: es exactamente el
   conjunto de piezas que define un proveedor. Construirlo a mano significa
   escribir sin revisar una versión reducida de algo que ya existe probado.
2. **Ya no es un proyecto aparte.** Spring Authorization Server se integró en
   **Spring Security 7**; el repositorio independiente se archivó en agosto de
   2026. Viene dentro de la Spring Security que este servicio ya usa, a una línea
   de dependencia: `spring-boot-starter-security-oauth2-authorization-server`,
   que resuelve a `spring-security-oauth2-authorization-server:7.1.1` bajo Boot
   4.1.1 — verificado.

## 2. Decisiones

| # | Decisión | Razón |
|---|---|---|
| 1 | **Authorization Code + PKCE**, un cliente OAuth por aplicación | Es la recomendación vigente para aplicaciones de navegador, y da a cada módulo una credencial que no sirve contra los demás |
| 2 | **`scope` mínimo; los permisos siguen en el claim `permissions`** | `scope` es lo que el cliente pide y el usuario consiente; los permisos son lo que un administrador concede. Para aplicaciones internas de primera parte el consentimiento es teatro, y los consumidores ya saben leer ese claim |
| 3 | **Sin prefijo de aplicación en las autoridades** | El `aud` ya fija la aplicación; `trafficflow.campanas.editar` duplicaría esa información en cada regla de `@PreAuthorize` |
| 4 | **Sesión SSO con Spring Session sobre JDBC** | Reutiliza `ma_auth`, que ya está migrada y probada en dos motores. Los despliegues dejan de cerrar la sesión de todo el mundo, y subir réplicas deja de ser una decisión pendiente |
| 5 | **Logout global** | En un ordenador compartido, quien pulsa «cerrar sesión» espera quedar fuera. «Volver al home» es navegación, no un logout |
| 6 | **`auth_app` sigue siendo el único registro de clientes** | El framework trae su propia tabla, pero usarla dejaría dos registros que deben concordar sin que nada los compare: la forma exacta del bug 8081/18080 que la fase 1 existió para arreglar |
| 7 | **Un solo cliente de Google, el de auth** | La aplicación sale del `client_id` de la petición, no del `aud` del token de Google. Se registra un origen en Google Cloud, no uno por panel |
| 8 | **Access token de 2 h por defecto, configurable por cliente** | Ver §7: sin refresh token, renovar es una redirección visible, y el TTL deja de ser invisible |

## 3. El flujo

```
Navegador
  ├─ home.mobile-americas.com   (MA-Platform-UI)  → cliente "admin"
  ├─ fgf.mobile-americas.com                      → cliente "fgf"
  └─ tf.mobile-americas.com                       → cliente "trafficflow"
             │
             │ 1. redirect a /oauth2/authorize?client_id=X&code_challenge=…
             ▼
  auth.mobile-americas.com
             │ 2. sin sesión → oauth2Login → Google (UN solo cliente)
             │ 3. vuelve → sesión SSO (Spring Session JDBC)
             │ 4. ¿tiene el usuario roles en X?  → AccessGrant
             │ 5. code → redirect al módulo
             ▼
  el módulo canjea code + verifier en /oauth2/token
             ▼
  access token (aud: X, permissions: […]) en memoria del módulo
             ▼
  módulo → su API con Authorization: Bearer
           la API valida firma (JWKS), aud: X y los permisos
```

## 4. Lo que escribimos — cuatro piezas

**`RegisteredClientRepository` sobre `auth_app`.** Traduce una fila de `auth_app`
a un `RegisteredClient`. Es lo que evita el segundo registro de la decisión 6.

**`OAuth2TokenCustomizer<JwtEncodingContext>`.** Mete `roles` y `permissions`
llamando a `AccessGrant.of(user, app, catálogo)`. **Aquí se enchufa todo el RBAC
de la fase 1 sin cambios**, y es la clase más pequeña de las cuatro.

**Validador de `/authorize`.** Rechaza con `access_denied` si el usuario no tiene
roles en el `client_id` pedido. Sin él, alguien sin acceso recibiría un token con
cero autoridades en vez de un error — el mismo fallo silencioso que la fase 1 ya
corrigió una vez en `grantDe`.

**`OidcUserService`.** Mapea el email de Google a `auth_user` y **rechaza al
desconocido en el login**, no más tarde. Reutiliza la normalización a minúsculas
y la comprobación de `email_verified` de la fase 1.

## 5. Resultados de la prueba de concepto

Se ejecutó el flujo completo contra Spring Security 7.1.1 antes de escribir este
documento. **Los tres puntos de extensión funcionan**, y el token emitido lleva
lo que debe:

```
iss: http://localhost:19999   sub: diego   aud: trafficflow
permissions: ['campanas:leer', 'campanas:editar']
roles: ['operador']           scope: ['openid']
```

El rechazo del cliente sin acceso devuelve al usuario **a su aplicación**:
`302 → …/cb?error=access_denied&error_description=…`.

Cinco hallazgos que el plan debe llevar por delante:

**1. Los paquetes se movieron.** El DSL vive en
`org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization`,
no en `…oauth2.server.authorization.config.annotation.web.configurers`.
**Todo el material publicado tiene los imports mal**, porque está escrito contra
el proyecto independiente. No copiar de tutoriales sin comprobar.

**2. La autoconfiguración no da un login funcionando.** Sin dos cadenas de
filtros declaradas a mano, `/oauth2/authorize` responde **401 con
`WWW-Authenticate: Bearer`**: queda protegido como *resource server* y nadie
entra. La cadena del authorization server **no autentica**; depende de la sesión
que establezca la otra cadena.

**3. El validador debe pasar `ctx.getAuthentication()` a su excepción.** Con
`null`, el usuario recibe un **400 crudo sin redirección**. Con el token, vuelve
a su aplicación con `error=access_denied`. Es la diferencia entre un callejón sin
salida y un flujo correcto, y no es evidente al escribirlo.

**4. Un cliente público no recibe refresh token.** Verificado con dos clientes
idénticos salvo el secreto: el confidencial obtiene `refresh_token`, el público
**no**, aunque declare el *grant*. Es una regla deliberada del framework, y un
SPA servido desde un bucket es necesariamente un cliente público. **Esto
determina la §7.**

**5. El DDL del framework no es portable.** Su propia cabecera lo dice: 15
columnas `blob` que PostgreSQL no admite y 16 `timestamp` que quiere como
`timestamptz`, más parámetros de conexión específicos para MySQL. Ver §6.

## 6. Datos

`auth_app` gana `redirect_uris`, `post_logout_redirect_uris` y los TTL por
cliente; **pierde `google_client_id`** (decisión 7). Entran las dos tablas de
Spring Session y la tabla de autorizaciones del framework. Sale
`auth_refresh_token`.

**La portabilidad se conserva, pero no gratis.** La fase 1 logró un único juego
de migraciones para ambos motores y eso no se sacrifica. Para las tablas del
framework:

- `blob` → **`text`**, que es lo que su propia cabecera indica para PostgreSQL y
  que MySQL acepta igual.
- `timestamp` → **`timestamp(6)`** en ambos, **en lugar de `timestamptz` en
  PostgreSQL**. La garantía de exactitud no se obtiene del tipo sino fijando
  **UTC en los dos extremos**: `TZ=UTC` y `-Duser.timezone=UTC` en el contenedor,
  y `preserveInstants=true&connectionTimeZone=UTC` en la URL de MySQL.

Sin ese anclaje a UTC, un `timestamp` sin zona se escribe y se lee según la zona
de la JVM: si cambia, las caducidades se desplazan y los tokens expiran antes o
después de lo debido. Es el tipo de fallo que no se ve hasta que se ve.

## 7. Tokens, TTL y renovación

Del hallazgo 4 se sigue todo lo demás. **Sin refresh token, renovar es una
redirección completa**: al cargar el módulo o al caducar el access token, ida a
`/oauth2/authorize`; como la sesión SSO existe, auth devuelve el código **sin
preguntar nada al usuario** y vuelve.

Eso hace el TTL **visible**, al contrario que en la fase 1, donde la renovación
era silenciosa y 15 minutos no se notaban. Con redirección, 15 minutos serían
unos 32 parpadeos en una jornada.

| | Valor | Dónde se configura |
|---|---|---|
| Access token | **2 h por defecto** | `auth_app`, por cliente |
| Sesión SSO | **12 h de inactividad** | configuración de Spring Session |
| Refresh token | **no se emite** | los clientes son públicos |

El TTL vive en `auth_app` y no como constante global, para que un panel interno
pueda tener 2 h y uno más sensible 15 minutos sin tocar código.

**El access token vive en memoria del módulo, nunca en `localStorage`.** Muere al
recargar, y entonces la redirección lo repone.

## 8. Logout

Global, mediante el `end_session_endpoint` que el framework ya expone, con
`post_logout_redirect_uris` por cliente desde `auth_app`.

Cerrar sesión mata la sesión SSO. Un **access token ya emitido sigue siendo
válido hasta que caduque** — hasta 2 h con el valor por defecto — porque un JWT
firmado no se puede desfirmar. Corte inmediato exigiría que cada backend
consultara una lista de revocación en cada petición, y eso convierte cada llamada
en un golpe a la base de datos. Se acepta la ventana.

⚠️ Con 2 h la ventana es ocho veces la de la fase 1. Para un cliente donde eso no
sea aceptable, la respuesta es bajarle el TTL en `auth_app`, que es justo para lo
que es configurable por cliente.

## 9. Qué sobrevive de la fase 1 y qué se reemplaza

**Sobrevive, y es la parte que más costó:** el modelo RBAC completo (`auth_user`,
`auth_role`, `auth_permission`, `auth_app`, el catálogo y la expansión de
comodines), `AccessGrant`, `JwtKeys` y el JWKS —el framework consume un
`JWKSource`, que es literalmente lo que ya expone—, las migraciones, la suite de
doble motor, el despliegue y el toolchain.

**Se reemplaza:** `GoogleIdentityVerifier` y `GoogleProperties`,
`auth_app.google_client_id`, `AuthController`, `CookieFactory`,
`CookieBearerTokenResolver`, `JwksController`, `MeController` (lo sustituyen el
ID token y `/userinfo`), `RefreshTokenStore` con su entidad y su repositorio,
`RsaTokenIssuer`, `TokenIssuer`, `AuthenticationService` y `AuthenticationResult`.

Nota irónica: la fase 1 estrechó `JwtKeys.jwkSource()` a *package-private* por
seguridad, anotando que reabrirlo exigiría un motivo escrito. Este es el motivo:
el framework necesita ese bean.

## 10. Pruebas

La suite de doble motor continúa, y las tablas del framework migran en ambos.

Lo nuevo: **un test del flujo completo** —authorize, código, canje, llamada con
bearer— y **el aislamiento entre aplicaciones**, con un token de `fgf` rechazado
por un *resource server* que espera `trafficflow`.

Para eso hace falta **simular Google**: un servidor local que sirva un documento
de descubrimiento y un JWKS falsos. Es infraestructura de test nueva y no
trivial, y conviene tratarla como una tarea propia y no como un detalle de otra.

## 11. Fases

| | Contenido |
|---|---|
| **2 (esta)** | El rediseño OAuth |
| **3** | CRUD de administración, que además gestiona *redirect URIs* y TTL por cliente |
| **4** | Integración de TrafficFlow y adaptación de `MA-Platform-UI` a cliente OAuth |

El CRUD baja de la 2 a la 3 porque ahora tiene más superficie que gestionar, y
porque construirlo antes sería administrar un modelo que está a punto de cambiar.

## 12. Riesgos

| Riesgo | Mitigación |
|---|---|
| El material publicado tiene los imports del proyecto archivado | Hallazgo 1 de §5, con los paquetes correctos escritos |
| El DDL del framework no es portable | §6, con el anclaje a UTC como condición |
| `MA-Platform-UI` debe reescribirse como cliente OAuth y su login desaparece | Coordinado con la sesión que migra ese repo a React 19 + Vite; ya avisada de no invertir en el login actual |
| Simular Google en los tests es infraestructura nueva | Tarea propia en el plan |
| La ventana de 2 h tras el logout | §8; bajar el TTL del cliente concreto |

## 13. Fuera de alcance

- Limitación de tasa en los endpoints del authorization server.
- Revocación inmediata de access tokens.
- Registro dinámico de clientes: `auth_app` se gestiona por migración hasta la
  fase 3.
- Refresh tokens para clientes confidenciales: hoy no hay ninguno.
