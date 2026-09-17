# MA-Platform-Authorization

Servicio de autorización de la plataforma: intercambia un ID token de Google
por un access token (15 min) y un refresh token (12 h) propios, en cookies
`HttpOnly`, y expone el JWKS para que otros servicios verifiquen esos tokens
sin llamar de vuelta a este servicio.

Spring Boot 4.1.1, Java 25, arquitectura de puertos y adaptadores. Sin
frameworks web en `domain`/`application` (ver `docs/superpowers/specs/`).

## Arrancar en local

Requiere una base MySQL local (o apuntar `spring.datasource.url` a otra) y
crea el esquema por Flyway al arrancar; no hace falta ejecutar nada a mano.

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

El perfil `dev` (`src/main/resources/application-dev.yml`) fija:

- `jdbc:mysql://localhost:3306/ma_platform_auth`, usuario/clave
  `ma-platform-user`/`ma-platform-password`.
- Orígenes CORS de `localhost:3000` y `localhost:5173`.
- La clave de firma de `src/main/resources/dev-keys/active.jwk`.

La app queda en `http://localhost:8081/authorization-api` y el puerto de
management (salud, `/actuator/info`) en `http://localhost:18081`.

Sin `SPRING_PROFILES_ACTIVE=dev`, el perfil por defecto exige
`DB_MA_PLATFORM_URL`, `DB_MA_PLATFORM_USER`, `DB_MA_PLATFORM_PASSWORD`,
`JWT_KEY_LOCATIONS` y `CORS_ALLOWED_ORIGINS` (o sus equivalentes en
`application.yml`) y **falla al arrancar si falta alguno**: es intencional,
no un bug — mejor un pod que no arranca que uno que arranca mal configurado.

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
**no se commitea**: se crea como Secret de Kubernetes y se monta como volumen
(ver más abajo), nunca como variable de entorno ni en el código.

`src/main/resources/dev-keys/active.jwk` es la única excepción, y solo porque
es de desarrollo puro: no protege nada real, nunca sale del perfil `dev`, y en
cualquier otro perfil `JWT_KEY_LOCATIONS` la sustituye por la ruta del Secret
montado en el pod.

## Ejecutar las pruebas

```bash
./gradlew test              # unitarias: dominio, casos de uso, capa web — sin Spring, sin BD
./gradlew integrationTest   # la suite completa dos veces: MySQL 8.4 y PostgreSQL 17 (Testcontainers)
./gradlew check             # ambas
```

`integrationTest` necesita un daemon de Docker disponible (Testcontainers).
No hay dependencia de red hacia Google: las claves de prueba se generan en el
propio test.

## Endpoints

```
Público
  POST /v1/auth/google            Google ID token → cookies + 204
  POST /v1/auth/refresh           rotación
  POST /v1/auth/logout            revoca la familia de refresh
  GET  /.well-known/jwks.json     claves públicas ← lo que consumen los clientes

Autenticado
  GET  /v1/auth/me                identidad, roles y permisos de la app del token

Administración  (Fase 2, aún no implementado en este repo)
  /v1/admin/apps          GET POST PUT DELETE
  /v1/admin/permissions   GET POST PUT DELETE
  /v1/admin/roles         GET POST PUT DELETE
  /v1/admin/users         GET POST PUT DELETE
  PUT /v1/admin/users/{id}/roles
  PUT /v1/admin/roles/{id}/permissions

Management  (puerto 18081, no expuesto al exterior; exposure.include=health,info)
  /actuator/health/{liveness,readiness}
  /actuator/info
```

Todas las rutas de la API (salvo `/actuator/**`, que vive en el puerto de
management) cuelgan del context path `/authorization-api`.

## Configurar un consumidor

Un consumidor **de servicio a servicio** (llama con cabecera
`Authorization: Bearer ...`) no necesita más que esto — sin escribir código,
solo configuración de Spring Security:

```yaml
spring.security.oauth2.resourceserver.jwt:
  jwk-set-uri: https://auth.mobile-americas.com/authorization-api/.well-known/jwks.json
  audiences: trafficflow            # sin esto, el aud NO se comprueba
  authorities-claim-name: permissions
  authority-prefix: ""
```

Las tres propiedades son necesarias, no solo la primera:

- **`audiences`**: sin ella, Spring Boot no instala el validador de `aud`, así
  que un token emitido para otra app se acepta igual. Esto es justo el
  aislamiento entre apps que este servicio garantiza (ver `SeguridadMySqlIT` /
  `SeguridadPostgresIT`); una configuración de consumidor sin `audiences` lo
  anula del lado del cliente.
- **`authorities-claim-name: permissions`** y **`authority-prefix: ""`**: por
  defecto, un resource server de Spring Security lee las autoridades del
  claim `scope`/`scp` con el prefijo `SCOPE_`. Los tokens de este servicio
  llevan los permisos en el claim `permissions`, sin prefijo. Sin estas dos
  propiedades, `hasAuthority('campanas:editar')` no encuentra nunca esa
  autoridad, aunque el token sea válido y esté bien firmado.

**Advertencia para un consumidor con interfaz de navegador**: el access token
se entrega como cookie `HttpOnly` (`ma_access`), no en el cuerpo de la
respuesta. Un consumidor de servicio a servicio no lo nota — usa la cabecera
`Authorization` como siempre. Pero un consumidor **cuyas peticiones salen del
navegador** no puede leer esa cookie para ponerla en una cabecera: necesita su
propio equivalente de `CookieBearerTokenResolver`
(`src/main/java/com/mobileamericas/authorization/web/security/CookieBearerTokenResolver.java`),
que resuelve el Bearer token a partir de la cookie cuando no hay cabecera
`Authorization`. Sin este resolver, un frontend que confía únicamente en la
cookie nunca autentica nada. Este es exactamente el trabajo de la Fase 3
(`MA-TrafficFlow-Backend`, `MA-TrafficFlow-UI`, `MA-Platform-UI`); vale la
pena tenerlo escrito ahora en vez de descubrirlo entonces.

## Despliegue

`Dockerfile`, `kubernetes/deployment.yaml` y `cloudbuild.yaml` en la raíz del
repo. Puntos que importa no olvidar:

- El `Service` que enruta a este pod vive en `MA-Platform-config`, no en este
  repositorio, y ya apunta a `8081`/`18081`. Este repo solo tiene que seguir
  escuchando ahí (`server.port: ${SERVER_PORT:8081}` en `application.yml`).
- La clave de firma se monta desde un `Secret` de Kubernetes
  (`ma-auth-jwt-keys`) como volumen, sembrado desde Secret Manager en Cloud
  Build — el mismo patrón que `MA-MtSender`, no el driver CSI de Secret
  Manager.
- `ADMIN_CLIENT_ID`, `FGF_CLIENT_ID` y `AUTH_SECRET` ya no existen: el mapeo
  cliente de Google → app vive en `auth_app.google_client_id`
  (`V2__datos_iniciales.sql`), no en variables de entorno.
- Pasos manuales fuera de este repo (no los resuelve ningún commit): generar
  el par de claves y el `Secret`, sembrarlo desde Secret Manager, poner los
  `google_client_id` y los emails reales en `auth_app`/`auth_user` (la
  migración deja marcadores `PENDIENTE-*` a propósito), crear el repositorio
  de Artifact Registry y reapuntar los *triggers* de Cloud Build, y crear la
  base de datos con `utf8mb4` en MySQL.
