# Reescritura de MA-Platform-Authorization

**Fecha:** 2026-09-16
**Branch:** `feat/spring-boot-4-java-25` (desde `origin/develop`)
**Estado:** diseño aprobado, pendiente de plan de implementación

---

## 1. Por qué

El servicio no está en uso. Esta es la razón técnica exacta, y no era conocida
hasta escribir este documento:

```yaml
# MA-Platform-config/gcp/prod/ma-authorization-prod-deployment-service.yaml
ports: [{ port: 8081, targetPort: 8081 }]
```
```yaml
# src/main/resources/application.yml
server.port: 18080        # literal: SERVER_PORT nunca se lee
```

El `Service` apunta a 8081. La aplicación escucha en 18080. **Nada puede llegar
al pod.** El `ConfigMap` define `SERVER_PORT: "8081"`, el `Dockerfile` lo expone
y `build.gradle` lo pasa como propiedad de sistema, pero `application.yml` fija
el puerto literal y ninguna de esas tres piezas tiene efecto.

Que el servicio esté parado es la oportunidad: no hay consumidores que romper y
solo hay 2 usuarios en la base de datos. Rehacerlo ahora cuesta este trabajo;
rehacerlo cuando TrafficFlow dependa de él cuesta bastante más.

### 1.1 Escalada de privilegios en `develop`

`JwtUtil.refreshAccessToken()`:

```java
DecodedJWT decodedAuthToken = JWT.decode(accessToken);   // decode, NO verify
verifyRefreshTokeAndGetDecoded(refreshToken);            // solo verifica el refresh
String newAccessToken = createAccessToken(
        decodedAuthToken.getIssuer(),
        app,
        mapClaims(decodedAuthToken.getClaims()));        // copia los roles sin verificar
```

El access token se decodifica **sin comprobar la firma** y sus claims —incluido
`roles`— se copian a un token nuevo que sí se firma. Con un refresh token válido
de una cuenta sin permisos, y un access token fabricado a mano con
`roles: [{admin: [...]}]`, el servicio devuelve ese rol firmado de verdad.

Es el fallo que define el diseño de la sección 5: **los roles del token nuevo se
leen de la base de datos, nunca del token anterior.**

### 1.2 Los demás defectos, y su destino

| Defecto | Destino |
|---|---|
| `GET /env` público: vuelca `System.getenv()`, que incluye `DB_MA_PLATFORM_PASSWORD` y `AUTH_SECRET` | Eliminado (§7) |
| `.anyRequest().permitAll()`: abierto por defecto; `PUT` sin protección | `.anyRequest().authenticated()` (§7) |
| `POST`/`PUT` de roles son *stubs* que devuelven `"Rol created OK"` | CRUD real (§6) |
| `new GoogleIdTokenVerifier(...)` por petición: anula la caché de claves de Google | `JwtDecoder` singleton con JWKS cacheado (§5) |
| Sesión de 1 h sin refresh posible | Refresh opaco rotativo (§5) |
| `server.port` literal ignora `SERVER_PORT` | `${SERVER_PORT:8081}` (§9) |
| `generate-ddl: true` contra producción | Flyway (§4) |
| Sin tests (`test` comentado en `build.gradle`) | §8 |
| Secreto JWT **simétrico**: quien valida puede falsificar | RS256 + JWKS (§5) |
| `iss` = email del usuario (debería ser el emisor) | Claims estándar (§5) |
| Cookies sin `HttpOnly`/`Secure`/`SameSite` (comentados) | §5 |
| `cloudbuild.yaml`: `gcr.io/sms-ma-shaplatform` (errata) vs `sms-ma-platform` al desplegar | §9 |
| `ENTRYPOINT` envuelve `java` en bash: `SIGTERM` no llega a la JVM | §9 |
| Sin probes de liveness/readiness | §9 |

## 2. Decisiones

| # | Decisión | Razón |
|---|---|---|
| 1 | **JWT asimétrico RS256 + JWKS**, refresh opaco rotativo en BD | Un consumidor puede validar sin poder falsificar. Con HMAC compartido, cualquier servicio comprometido emite tokens de admin |
| 2 | **UUID + un único DDL**, JPA, Flyway, Testcontainers contra MySQL 8 **y** PostgreSQL 17 | El autoincremento es el único constructo sin sintaxis común; con UUID desaparece y basta un juego de migraciones. Los tests lo verifican en cada build |
| 3 | **CRUD completo por API** de las 5 entidades + `auth_audit` | Operar sin despliegues. La auditoría compensa que los cambios de estructura ya no queden en git |
| 4 | **Permisos `recurso:verbo`** con comodín | `create` a secas no expresa "edita campañas pero no toca redes", que es el caso normal en TrafficFlow |
| 5 | Secretos: **Secret de Kubernetes**, no driver CSI | Es el patrón de los otros 18 servicios. El CSI no lo usa nadie en la plataforma |
| 6 | Los `Service` se **quedan en `MA-Platform-config`**, sin tocar | El desajuste está solo en el lado de la aplicación: el `Service` ya apunta a 8081 y el `ConfigMap` ya define `SERVER_PORT: "8081"`. Arreglando `application.yml` concuerdan sin tocar el otro repo. Se revisa cuando esto esté funcionando |
| 7 | Branch desde `origin/develop` | Es el estado más avanzado y el que `MA-Platform-UI` consume |

### 2.1 Versiones

Verificadas el 2026-09-16, no de memoria:

| Componente | Versión | Nota |
|---|---|---|
| Spring Boot | **4.1.1** | mínimo Java 17, compatible hasta Java 26 |
| Spring Framework | 7.0.9+ | viene con Boot 4.1 |
| Java | **25 LTS** | Temurin 25.0.4 ya instalado en la máquina de desarrollo |
| Gradle | **9.6** | el wrapper está en 8.7 y hay que subirlo |
| Jakarta EE | 11 | Hibernate 7.x |
| Jackson | **3** | por defecto en Boot 4: cambian los paquetes |
| springdoc-openapi | **3.1.1** | la línea 2.x se queda en Boot 3.5 |

## 3. Arquitectura

### 3.1 Dónde está de verdad el acoplamiento al motor

Hoy no está en el driver: está en que `UserEntity` —una clase JPA— es la moneda
de cambio de toda la aplicación. `UserService`, `AuthorizationServiceImpl` y
`UserDetailsServiceImpl` reciben y devuelven entidades JPA. De ahí el
`FetchType.EAGER` en todas las relaciones: es la única forma de que el grafo
sobreviva fuera de la transacción.

Con esa estructura, cambiar de motor obliga a revisar cada consumidor. Así que
**el dominio pasa a ser records de Java sin una sola anotación de framework** y
las entidades JPA quedan encerradas en el adaptador.

```
com.mobileamericas.authorization
├── domain/              records puros: App, User, Role, Permission, AccessGrant
│                        cero imports de jakarta.* y de org.springframework.*
├── application/
│   ├── port/            UserRepository, RoleRepository, AppRepository,
│   │                    RefreshTokenStore, IdentityVerifier, TokenIssuer, AuditLog
│   └── service/         AuthenticationService, AuthorizationService, AdminService
├── adapter/
│   ├── persistence/     entidades JPA, impls de los puertos, mappers
│   ├── google/          GoogleIdentityVerifier (JwtDecoder con JWKS cacheado)
│   └── token/           RsaTokenIssuer, RefreshTokenStoreJpa
└── web/
    ├── AuthController, AdminController, JwksController
    ├── ProblemDetail handlers
    └── security/        SecurityConfig
```

Criterio de verificación: **`domain/` y `application/` se testean sin Spring y
sin base de datos.** Si un test de esas capas necesita un contenedor, la
frontera está mal puesta.

Mantiene el patrón puerto/adaptador que el código actual ya insinúa
(`repositories/UserRepository` + `infrastructure/persistence/JpaUserRepository`);
solo lo completa y lo aplica de forma consistente.

### 3.2 Java 25

Dos usos con beneficio medible, no por novedad:

- **Records** para el dominio: inmutables, sin Lombok, sin `@Setter` en un
  modelo que no debe mutar.
- **Hilos virtuales** (`spring.threads.virtual.enabled: true`): el servicio es
  puro E/S — Google, JWKS, base de datos — que es exactamente su caso favorable.

No se usan *preview features*: nada aquí las necesita y obligarían a
`--enable-preview` en tiempo de ejecución.

## 4. Modelo de datos

### 4.1 Un único DDL

Claves `VARCHAR(36)` con UUID generado en la aplicación. Tipos restringidos a
los que **MySQL 8 y PostgreSQL 17 aceptan con sintaxis idéntica**: `VARCHAR`,
`BIGINT`, `BOOLEAN`, `TIMESTAMP(6)`, `TEXT`.

```
auth_app             (id, name UNIQUE, google_client_id UNIQUE, url,
                      active, created_at, updated_at)
auth_permission      (id, app_id→app, resource, verb, description, created_at)
                      UNIQUE(app_id, resource, verb)
auth_role            (id, name, app_id→app, description, created_at, updated_at)
                      UNIQUE(name, app_id)
auth_user            (id, email UNIQUE, full_name, active, created_at, updated_at)
auth_user_role       (user_id, role_id)                        PK compuesta
auth_role_permission (role_id, permission_id)                  PK compuesta
auth_refresh_token   (id, user_id, app_id, token_hash UNIQUE, family_id,
                      expires_at, revoked_at, used_at, created_at)
auth_audit           (id, actor_email, action, entity, entity_id,
                      payload TEXT, created_at)
```

Decisiones deliberadas:

- **`payload TEXT`, no `JSON`.** MySQL tiene `JSON` y PostgreSQL tiene `jsonb`;
  no son la misma sintaxis. `TEXT` con JSON serializado sí es portable. Si algún
  día hace falta consultar dentro del payload, será una migración específica por
  motor y consciente, no una sorpresa.
- **`auth_app.google_client_id`.** El mapeo `clientId → app` se muda de
  `application.yml` a la base de datos. Añadir una aplicación deja de requerir
  un despliegue, y **desaparecen `ADMIN_CLIENT_ID`, `FGF_CLIENT_ID` y el paso
  `envsubst` de `cloudbuild.yaml`**. Contrapartida aceptada: un administrador
  puede registrar un client ID ajeno; queda auditado y es acción privilegiada.
- **`auth_permission.app_id`.** Hoy los permisos son globales, lo cual no tiene
  sentido: `campanas:editar` no significa nada dentro de la app `admin`.
- Todo lo que hoy admite `NULL` sin motivo (`name`, `email`) pasa a `NOT NULL`.
- El esquema actual es `utf8mb3`, que no cubre Unicode completo. El nuevo es
  `utf8mb4` en MySQL y UTF-8 en PostgreSQL, que es su único modo.

### 4.2 Permisos `recurso:verbo`

Verbos: `crear`, `leer`, `editar`, `borrar`. Comodín `*` admitido en cualquiera
de las dos posiciones.

**Los comodines se expanden en el momento de emitir el token**, nunca viajan en
él. El catálogo de recursos de una app es
`SELECT DISTINCT resource FROM auth_permission WHERE app_id = ? AND resource <> '*'`,
así que no hace falta una tabla extra. Consecuencia buscada: el token lleva
siempre autoridades concretas y **cualquier *resource server* estándar funciona
con `hasAuthority` sin una línea de código propio** — pero sí con dos líneas de
configuración, porque por defecto un *resource server* lee las autoridades del
claim `scope`/`scp` y con el prefijo `SCOPE_`:

```yaml
spring.security.oauth2.resourceserver.jwt:
  authorities-claim-name: permissions   # no 'scope'
  authority-prefix: ""                  # no 'SCOPE_'
```

Sin configuración, no hay código propio pero tampoco autoridades: `hasAuthority`
no encontraría nada. Las tres propiedades que todo consumidor necesita —estas dos
más `audiences`— van juntas en el README de §6.

De ahí se sigue una obligación que no es opcional: **cada app debe declarar sus
permisos concretos** (su catálogo), porque el comodín se expande contra ellos.
Una app que solo tuviera filas con `*` expandiría a un conjunto vacío y su
administrador se quedaría **sin ninguna autoridad**, en silencio. Dos defensas:

1. `V2__datos_iniciales.sql` inserta el catálogo concreto de `admin` y de `fgf`
   (`apps`, `permisos`, `roles`, `usuarios` × `crear leer editar borrar`) antes
   de asignar ningún comodín.
2. Dar de alta una app, o asignar un rol con comodín a una app sin permisos
   concretos, se rechaza con un error explícito. Un test cubre el caso.

### 4.3 Migración de los datos existentes

El volcado de producción del 2026-09-16 tiene 2 apps, 5 permisos, 5 roles,
**2 usuarios**, 4 asignaciones usuario→rol y 16 rol→permiso. Se reproduce entero
en `V2__datos_iniciales.sql` con equivalencia exacta de privilegios:

| Rol | Permisos hoy | Permisos nuevos | Cambio |
|---|---|---|---|
| `admin@admin` | view read create update delete | `*:*` | ninguno |
| `support@admin` | view read update | `*:leer` `*:editar` | ninguno |
| `analyst@admin` | view read | `*:leer` | ninguno |
| `admin@fgf` | view read create update delete | `*:*` | ninguno |
| `user@fgf` | view | `*:leer` | ninguno |

`view` y `read` eran redundantes y ambos colapsan en `leer`. `create`, `update`
y `delete` se mantienen distinguibles como `crear`, `editar` y `borrar`: mapear
los tres a un único `escribir` habría **concedido a `support@admin` un permiso
de borrado que hoy no tiene**.

Los 2 usuarios conservan su email como identidad; solo cambia su clave primaria
a UUID.

## 5. Tokens

### 5.1 Access token

RS256, 15 minutos, `kid` en la cabecera:

```json
{
  "iss": "https://auth.mobile-americas.com",
  "sub": "8f14e45f-ceea-4d3e-9b1a-0a3f6c2d5e71",
  "aud": "trafficflow",
  "email": "persona@ejemplo.com",
  "name": "Nombre Apellido",
  "roles": ["operador"],
  "permissions": ["campanas:leer", "campanas:editar", "redes:leer"],
  "jti": "…", "iat": 1789600000, "exp": 1789600900
}
```

- `sub` es el UUID del usuario, no el email: el email puede cambiar y `sub` debe
  ser estable.
- `aud` es el nombre de la app. Un token emitido para `admin` no debe valer
  contra TrafficFlow, y de eso se encarga el propio *resource server* sin código
  nuestro — **pero solo si el consumidor declara la audiencia esperada**:

  ```yaml
  spring.security.oauth2.resourceserver.jwt:
    jwk-set-uri: https://auth.mobile-americas.com/authorization-api/.well-known/jwks.json
    audiences: trafficflow      # ← SIN esta línea, el aud NO se comprueba
  ```

  ⚠️ Esto es obligatorio, no una opción. Verificado en el bytecode de Spring Boot
  4.1.1 (`JwtDecoderConfiguration`): el validador de `aud` se añade únicamente
  cuando `audiences` no está vacío. Con `jwk-set-uri` a secas, el decodificador
  ejecuta `JwtValidators.createDefault()`, que comprueba `exp`, `nbf` y el emisor
  si está configurado, y **nunca** `aud`. Un consumidor que configure solo el
  JWKS aceptará tokens de `admin` en el servicio de `trafficflow`.

  Una versión anterior de este documento afirmaba el aislamiento sin esa
  condición. Era falso y habría producido exactamente ese agujero en la fase 3.
- `permissions` son autoridades concretas, ya expandidas (§4.2).

### 5.2 Refresh token

Opaco, 256 bits de `SecureRandom`. En la base de datos se guarda **solo su
SHA-256**, nunca el valor: un volcado de `auth_refresh_token` no permite
suplantar a nadie.

Rotativo: cada uso invalida el anterior y emite uno nuevo de la misma
`family_id`. Si llega un token ya rotado, **se revoca la familia entera** — es la
señal de que alguien obtuvo una copia.

Y lo que cierra el agujero de §1.1: **al renovar, los roles y permisos se
resuelven consultando la base de datos por `user_id`.** Los claims del access
token anterior no se leen, así que fabricar uno no aporta nada. El access token
ni siquiera se envía en la renovación.

Duraciones (configurables): access 15 min, refresh 12 h **de inactividad, no de
sesión absoluta**: cada rotación calcula `now + refreshTtl`, así que un cliente
que renueve dentro de la ventana mantiene la sesión indefinidamente. Es la
lectura estándar de la industria y es deliberada, pero la redacción anterior
—"refresh 12 h" a secas— se leía como un tope de sesión. Si algún día se quiere
ese tope, hace falta comprobar la antigüedad de la familia en `rotate()`.

Revocación de un rol:
efectiva en ≤ 15 min, o inmediata revocando la familia.

### 5.3 Cookies

`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Y el token **deja de devolverse
en el cuerpo de la respuesta**: hoy va en el body y `MA-Platform-UI` lo guarda en
`localStorage`, legible por cualquier XSS.

⚠️ Esto rompe `MA-Platform-UI`, que lee la cookie desde JavaScript
(`userSessionUtil.tsx`). El arreglo está en el alcance de la fase 3 (§10).

### 5.4 Rotación de claves

El JWKS publica **varias claves públicas a la vez**, cada una con su `kid`. Rotar
es: añadir la clave nueva al JWKS, empezar a firmar con ella, y retirar la vieja
cuando expire el último token que firmó (≤ 15 min). Ningún token vivo se
invalida. Es una operación deliberada, no automática — y por eso el driver CSI,
cuyo argumento principal es la rotación automática, no aporta aquí.

### 5.5 Verificación del token de Google

`GoogleIdentityVerifier` usa un `JwtDecoder` de Spring Security **singleton**,
apuntando al JWKS de Google, con caché de claves. Sustituye al
`new GoogleIdTokenVerifier(new NetHttpTransport(), …)` por petición del código
actual, que hace una ida y vuelta extra a Google en cada llamada. La `aud` del
token se resuelve contra `auth_app.google_client_id` (cacheado).

Esto elimina la dependencia de `com.google.api-client`.

## 6. API

```
Público
  POST /v1/auth/google            Google ID token → cookies + 204
  POST /v1/auth/refresh           rotación
  POST /v1/auth/logout            revoca la familia de refresh
  GET  /.well-known/jwks.json     claves públicas ← lo que consume MS-2

Autenticado
  GET  /v1/auth/me                identidad, roles y permisos de la app del token

Administración  (@PreAuthorize por permiso, todo auditado)
  /v1/admin/apps          GET POST PUT DELETE
  /v1/admin/permissions   GET POST PUT DELETE
  /v1/admin/roles         GET POST PUT DELETE
  /v1/admin/users         GET POST PUT DELETE
  PUT /v1/admin/users/{id}/roles
  PUT /v1/admin/roles/{id}/permissions

Management  (puerto 18081, no expuesto al exterior)
  /actuator/health/{liveness,readiness}
  /actuator/info
```

`GET /env` desaparece. Lo sustituye `/actuator/info` con datos no sensibles, en
el puerto de management.

Los errores pasan a `application/problem+json` (RFC 7807), que es lo que el
cliente de `MA-TrafficFlow-UI` ya sabe parsear (`src/api/problem.ts`). El
`ResponseDto` actual, que devuelve `e.getStackTrace()[0]` al cliente, se
elimina: filtra rutas de clases y números de línea a quien llame.

Cada escritura de `/v1/admin/**` escribe en `auth_audit` **en la misma
transacción** que el cambio. No hay forma de saltárselo.

## 7. Seguridad

- `.anyRequest().authenticated()`: denegar por defecto. Las excepciones se
  enumeran explícitamente y son solo las cuatro rutas públicas de §6.
- `@PreAuthorize` sobre autoridades concretas, nunca sobre nombres de rol:
  `hasAuthority('usuarios:editar')`, no `hasRole('admin')`.
- CORS por lista de orígenes configurada (`develop` ya lo hace bien);
  nunca `*` con `allowCredentials`.
- Sin `PasswordEncoder` de texto plano: no hay contraseñas en este servicio, la
  identidad la pone Google.
- La clave privada se monta desde un Secret de Kubernetes y **no se registra en
  ningún log ni se expone en ningún endpoint**.

Fuera de alcance, anotado para después: limitación de tasa en `/v1/auth/google`
y `/v1/auth/refresh`.

## 8. Pruebas

| Nivel | Contenido | Dependencias |
|---|---|---|
| Unitario | dominio y casos de uso | ninguna: sin Spring, sin BD |
| Web | `@WebMvcTest` con verificador y emisor falsos | ninguna |
| Integración | la suite completa **dos veces**: MySQL 8 y PostgreSQL 17 | Testcontainers |

Las claves RSA se generan en el propio test: **cero dependencia de Google** en
la suite. Ejecutar la misma suite contra los dos motores es lo que convierte
"agnóstico del motor" en un hecho que verifica el build, no una promesa.

Tres pruebas que existen por un motivo concreto:

1. **Escalada de privilegios de §1.1**: access token forjado con `roles: [admin]`
   + refresh token válido de una cuenta sin permisos → debe fallar, y los
   permisos del token emitido deben ser los de la base de datos.
2. **Aislamiento entre apps**: un token con `aud: admin` rechazado por un
   *resource server* configurado para `trafficflow`.
3. **Reutilización de refresh**: usar un token ya rotado revoca la familia
   entera.

El contrato OpenAPI se genera como artefacto del build. `MA-TrafficFlow-UI` ya
tiene `openapi-typescript` y un `npm run types`, así que obtiene cliente tipado
sin trabajo adicional.

## 9. Despliegue

Cloud Build + GKE, como hasta ahora. Cambios:

**Correcciones**

```diff
# cloudbuild.yaml
- _IMAGE_NAME: gcr.io/sms-ma-shaplatform/ma-authorization
+ _IMAGE_NAME: us-east1-docker.pkg.dev/sms-ma-platform/ma-platform/ma-authorization

# Dockerfile
- RUN echo "#!/bin/bash \n java -jar ./ma-authorization.jar" > ./entrypoint.sh
- ENTRYPOINT ["./entrypoint.sh"]                           # SIGTERM llega a bash
+ ENTRYPOINT ["java", "-jar", "/usr/app/ma-authorization.jar"]  # SIGTERM llega a la JVM
- FROM eclipse-temurin:17-jdk-jammy
+ FROM eclipse-temurin:25-jre-alpine
+ USER 1000:1000

# application.yml
- port: 18080
+ port: ${SERVER_PORT:8081}
```

El `ENTRYPOINT` en forma exec es lo que hace que
`terminationGracePeriodSeconds: 60` sirva de algo: hoy `SIGTERM` lo recibe bash
y la JVM muere sin apagado ordenado.

**Manifiestos**

Los dos `Service` se quedan en `MA-Platform-config/gcp/prod/` y **no se tocan**.

No hace falta: el `Service` ya declara `port: 8081, targetPort: 8081` y el
`ConfigMap` ya define `SERVER_PORT: "8081"`. El único lado equivocado es
`application.yml`, que fija 18080 literal e ignora la variable. Con
`port: ${SERVER_PORT:8081}` los dos repos concuerdan sin modificar ninguno de
los 18 servicios que comparten ese patrón.

El puerto de management (18081) **no se expone** en ningún `Service`, que es lo
correcto: `/actuator/**` no debe ser alcanzable desde fuera del clúster.

Queda anotado para revisar cuando el servicio esté funcionando: si algún día
`Deployment` y `Service` vuelven a divergir, la causa será que viven en repos
distintos y nada los compara.

Se añaden al `Deployment`:

```yaml
ports:
  - { name: http, containerPort: 8081 }
  - { name: management, containerPort: 18081 }
livenessProbe:
  httpGet:  { path: /actuator/health/liveness,  port: management }
  initialDelaySeconds: 20
  periodSeconds: 10
readinessProbe:
  httpGet:  { path: /actuator/health/readiness, port: management }
  initialDelaySeconds: 10
  periodSeconds: 5
env:
  - name: JAVA_TOOL_OPTIONS
    value: "-XX:MaxRAMPercentage=50 -XX:InitialRAMPercentage=25"
```

Sin `readinessProbe`, Kubernetes manda tráfico al pod antes de que Flyway y el
pool de conexiones estén listos. Sin `livenessProbe`, un pod colgado no se
reinicia nunca. `JAVA_TOOL_OPTIONS` y los `ports:` nombrados se toman de
`MA-MtSender`, que ya los tiene.

**Secretos**

Patrón de la plataforma, no driver CSI (§2, decisión 5):

```yaml
- name: JWT_PRIVATE_KEY
  valueFrom:
    secretKeyRef: { name: ma-auth-jwt-keys, key: private-key }
```

El Secret se siembra desde Secret Manager en Cloud Build, igual que hace
`MA-MtSender` con sus claves SSH (`gcloud secrets versions access latest
--secret=…`). `AUTH_SECRET` desaparece, y con él el `envsubst` de los client IDs
(§4.1).

⚠️ Migrar de `gcr.io` a Artifact Registry afecta a los *triggers* de Cloud Build,
que se configuran fuera de git. Es un paso manual a coordinar en el despliegue.

## 10. Fases

Tres fases independientemente desplegables.

**Fase 1 — Núcleo.** Boot 4.1.1 + Java 25 + Gradle 9. Persistencia nueva (UUID,
Flyway, Testcontainers dual). Autenticación: Google → JWT RS256 + JWKS + refresh
opaco rotativo. `/v1/auth/*`, `/v1/auth/me`, JWKS. `/env` eliminado, seguridad
cerrada por defecto. Despliegue arreglado (§9).
→ *Al acabar esta fase, TrafficFlow ya se puede autenticar y autorizar.*

> ## ⚠️ Renumeración: la fase 2 ya no es el CRUD
>
> El 2026-09-18 se intercaló el rediseño de la emisión de tokens sobre Spring
> Authorization Server, en
> `docs/superpowers/specs/2026-09-18-oauth-authorization-server-design.md`.
> **Ese documento sustituye la §5 (Tokens) de este**, y renumera:
> **fase 2 = rediseño OAuth · fase 3 = CRUD · fase 4 = integración**.
>
> El motivo, en una línea: este diseño asumió una topología de cliente que no es
> la real. Con el *home* y los módulos en subdominios hermanos y buckets
> independientes, la entrega del token solo por cookie `HttpOnly` no permite al
> módulo llamar a su propia API en otro host.
>
> **Y la escalada que los criterios de abajo intentaban prevenir queda resuelta
> por construcción**: cada aplicación recibe su propio token con su propia
> audiencia, así que no existe un token compartido que pueda satisfacer la
> comprobación de autoridad de otra. Lo que sobrevive de esos criterios es el
> primero, convertido en requisito permanente de todo consumidor: **declarar
> `audiences`, o el `aud` no se comprueba**.

**Fase 2 — Administración** *(ahora fase 3)*. CRUD de las 5 entidades,
`auth_audit`, `@PreAuthorize` por permiso, OpenAPI publicado.

> ### ⚠️ Criterios de entrada — no son recomendaciones
>
> Ambos salieron de la revisión final de la fase 1 y **tienen que estar antes de
> que exista el primer endpoint protegido con `@PreAuthorize`**, no después.
>
> **1. `/v1/admin/**` debe exigir además que `aud` sea la aplicación `admin`.**
> Las cadenas de autoridad **no están cualificadas por aplicación**, así que
> `aud` es lo único que separa los espacios de nombres. El camino concreto, con
> los datos ya sembrados: `usuario2` tiene `analyst@admin` —que es `*:leer`, solo
> lectura en `admin`— y además `admin@fgf`, que es `*:*`. El catálogo de `fgf` es
> `{usuarios}`, luego un token con `aud: fgf` lleva
> `permissions: [usuarios:crear, usuarios:leer, usuarios:editar, usuarios:borrar]`.
> Sin ligar `aud` al endpoint, `hasAuthority('usuarios:borrar')` sobre el API de
> administración quedaría satisfecho por ese token: **un analista de `admin`
> podría borrar usuarios de `admin`.** Es la escalada de §1.1 por otra puerta.
>
> La fase 1 solo comprueba **presencia** de `aud` en `selfJwtDecoder`, a
> propósito: `/v1/auth/me` sirve tokens de cualquier aplicación por diseño, así
> que restringir `aud` globalmente lo rompería, y en la fase 1 no existe ni un
> `hasAuthority` que pudiera colisionar. La ligadura correcta es por endpoint.
>
> **2. El rethrow de `AccessDeniedException` en `ApiExceptionHandler` necesita
> test.** Está cableado y verificado por inspección, pero no puede ejercitarse
> sin un endpoint protegido. Si está mal, una denegación de autorización se
> reporta como **500 en lugar de 403** en cuanto llegue el CRUD.

**Fase 3 — Integración.** Alta de la app `trafficflow` con sus permisos;
*resource server* en `MA-TrafficFlow-Backend` (hoy sin `spring-boot-starter-security`,
pero con `serviceIdentity: bearer JWT` ya declarado en
`contracts/openapi/admin-api.yaml`); autenticación en `MA-TrafficFlow-UI`;
y adaptación de `MA-Platform-UI` a las cookies `HttpOnly` (§5.3).

⚠️ Corregido el 2026-09-17, con datos del propio equipo de TrafficFlow. Una
versión anterior de este párrafo decía que el trabajo en el panel era «cabecera
`Authorization`… un único punto: `peticion()` en `src/api/client.ts`». Era falso
por dos motivos, y ambos habrían hecho subestimar la fase:

1. **Contradecía §5.3 de este mismo documento.** El access token se entrega en
   una cookie `HttpOnly`, así que el JavaScript del panel no puede leerlo ni
   ponerlo en una cabecera. Lo que necesita es `credentials: 'include'`, y
   `MA-TrafficFlow-Backend` necesita un `BearerTokenResolver` que lea la cookie
   `ma_access` — el mismo patrón que `web/security/CookieBearerTokenResolver`.
   Eso cambia el diseño de la integración, no sólo su configuración.
2. **No es un único punto.** El panel **no tiene hoy ninguna pantalla de login ni
   nada que llame a `/v1/auth/*`**: hay que construir el Google Sign-In, el
   estado de sesión, el logout y la renovación ante un 401. Lo que sí está hecho
   es el tratamiento del rechazo — `NoAutenticadoError` y `SinPermisoError`
   separados, y diez pantallas que ya distinguen «te cortaron el acceso» de «no
   hay datos», con pruebas por pantalla. Falta quien produzca el token.

Confirmado también desde ese lado: los seis recursos del catálogo de permisos son
`redes`, `endpoints` de postback, `servicios`, `campanas`, `enlaces` y `reglas`.
Los verbos exactos que usa cada pantalla los aporta ese equipo cuando se abra la
fase, para no inventar permisos que nadie comprueba ni dejar fuera alguno que sí.

## 11. Riesgos

| Riesgo | Mitigación |
|---|---|
| **Las rutas cambian de `/v1/authorization/*` a `/v1/auth/*`**, y `GET /role` pasa a `GET /v1/auth/me`. `MA-Platform-UI` llama a las antiguas | Fase 3, coordinado. Se acepta romperlas porque el servicio no está en uso (§1) y mantener dos juegos de rutas por un consumidor que también tocamos no se paga |
| `MA-Platform-UI` deja de funcionar con cookies `HttpOnly` | Fase 3, coordinado. Su axios ya manda `withCredentials: true`, así que el cambio es pequeño |
| Un comodín en una app sin permisos concretos deja a su administrador sin autoridades | §4.2: catálogo obligatorio, validación al alta y un test que lo cubre |
| Migrar a Artifact Registry toca *triggers* fuera de git | Paso manual explícito en el despliegue de fase 1 |
| Los cambios de estructura dejan de estar en git (CRUD completo) | `auth_audit` en la misma transacción que el cambio |
| Jackson 3 cambia paquetes | Reescritura completa; no hay migración incremental que gestionar |
| Boot 4 modulariza los jars: cambian nombres de dependencias | Se resuelven al construir; el BOM de Boot los fija |

## 12. Fuera de alcance

- Limitación de tasa en los endpoints de autenticación.
- Panel de administración propio (el CRUD de fase 2 es su base, pero la interfaz
  no está en este alcance).
- Migración de producción de MySQL a PostgreSQL: este diseño la hace posible sin
  cambios de código —solo URL y driver— pero ejecutarla es un trabajo aparte.

  ⚠️ Corregido tras la revisión final: esa afirmación era **falsa** tal como
  estaba. La colación por defecto de MySQL (`utf8mb4_0900_ai_ci`) hace
  `findByEmail` y `UNIQUE (email)` insensibles a mayúsculas; PostgreSQL es
  sensible. Verificado contra contenedores reales:
  `findByEmail("USUARIO1@PENDIENTE.LOCAL")` devolvía presente en MySQL y ausente
  en PostgreSQL. Cualquier usuario cuyo casing almacenado difiriera del que envía
  Google habría dado 403 tras la migración, en silencio.
  Resuelto normalizando el email a minúsculas en la frontera
  (`GoogleIdentityVerifier` y `UserRepositoryAdapter.findByEmail`, con
  `Locale.ROOT`), con un test de doble motor que compara las dos respuestas.
  **Los identificadores son insensibles a mayúsculas por decisión de diseño**, no
  por accidente de colación — que es lo que eran antes.
- Flujos OAuth2 para terceros: se descartó Spring Authorization Server por
  desproporcionado para dos SPAs internas.
