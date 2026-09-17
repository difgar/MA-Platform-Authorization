# Fase 1 — Núcleo de autenticación y autorización · Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar `MA-Platform-Authorization` corriendo sobre Spring Boot 4.1.1 y Java 25, emitiendo tokens RS256 verificables por JWKS contra una base de datos agnóstica del motor, y desplegado de forma que el tráfico llegue al pod.

**Architecture:** Puertos y adaptadores. `domain/` son records de Java sin anotaciones de framework y `application/` son casos de uso que solo conocen puertos; ambos se testean sin Spring y sin base de datos. Los adaptadores (JPA, Google, firma de tokens) quedan en `adapter/`. La identidad la pone Google; este servicio la traduce a un token propio firmado con clave asimétrica cuya pública se publica en un JWKS.

**Tech Stack:** Java 25 (Temurin) · Spring Boot 4.1.1 · Spring Framework 7.0.9 · Spring Security 7 · Gradle 9.6.1 · Flyway · Hibernate 7 · Nimbus JOSE+JWT (vía `spring-security-oauth2-jose`) · Testcontainers · JUnit 5 · MySQL 8.4 y PostgreSQL 17

**Spec:** `docs/superpowers/specs/2026-09-16-reescritura-autorizacion-design.md`

**Branch:** `feat/spring-boot-4-java-25` (ya creado desde `origin/develop`)

## Global Constraints

Estos requisitos aplican a **todas** las tareas:

- **Java 25**, Spring Boot **4.1.1**, Gradle **9.6.1**. No usar *preview features* (obligarían a `--enable-preview` en ejecución). springdoc-openapi **3.1.1** es la versión para Boot 4, pero **no entra en esta fase**: el contrato OpenAPI se publica en la fase 2, con el CRUD.
- **Jackson 3** es el de Boot 4: los paquetes son `tools.jackson.*`, no `com.fasterxml.jackson.databind.*`. Las anotaciones (`@JsonProperty`, `@JsonIgnore`) siguen en `com.fasterxml.jackson.annotation`. **No declarar un `ObjectMapper` propio**: Boot lo autoconfigura.
- **`domain/` y `application/` no importan `jakarta.*` ni `org.springframework.*`.** Si un test de esas capas necesita un contenedor, la frontera está mal puesta.
- **Un único juego de migraciones Flyway.** Solo estos tipos, que MySQL 8 y PostgreSQL 17 aceptan con sintaxis idéntica: `VARCHAR`, `BIGINT`, `BOOLEAN`, `TIMESTAMP(6)`, `TEXT`. Prohibidos: `AUTO_INCREMENT`, `IDENTITY`, `JSON`/`jsonb`, `ENUM`, `DEFAULT CHARSET=`, `ENGINE=`.
- **Claves primarias `VARCHAR(36)`** con UUID generado en la aplicación. Nunca autoincremento.
- **Toda prueba de integración se ejecuta contra los dos motores.** Una prueba que solo corra en uno no cuenta como hecha.
- **Ninguna clave privada ni secreto en logs, en respuestas o en endpoints.**
- Verbos de permiso: exactamente `crear`, `leer`, `editar`, `borrar`. Comodín `*`.
- Mensajes de commit en español, en imperativo, con `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` al final.

## Estructura de ficheros

| Fichero | Responsabilidad | Tarea |
|---|---|---|
| `build.gradle`, `gradle/wrapper/*` | Toolchain, dependencias, *source set* de integración | 1 |
| `domain/Verb.java` | Los cuatro verbos | 2 |
| `domain/Permission.java` | Par recurso+verbo, comodines, expansión | 2 |
| `domain/App.java`, `Role.java`, `User.java` | Records del dominio | 2 |
| `domain/AccessGrant.java` | Lo que un usuario puede hacer en una app | 2 |
| `db/migration/V1__esquema.sql` | DDL portable | 3 |
| `db/migration/V2__datos_iniciales.sql` | Los datos del volcado de producción | 3 |
| `adapter/persistence/*Entity.java` | Entidades JPA (encerradas aquí) | 4 |
| `adapter/persistence/*RepositoryJpa.java` | Implementaciones de los puertos | 4 |
| `application/port/*.java` | Puertos de salida | 2, 4, 5, 6, 7 |
| `adapter/token/RsaTokenIssuer.java` | Firma RS256, claims, `kid` | 5 |
| `adapter/token/JwtKeys.java` | Carga de claves y conjunto JWKS | 5 |
| `adapter/token/RefreshTokenStoreJpa.java` | Hash, rotación, familia, reutilización | 6 |
| `adapter/google/GoogleIdentityVerifier.java` | `JwtDecoder` singleton + resolución de app | 7 |
| `application/service/AuthenticationService.java` | El caso de uso completo | 8 |
| `web/AuthController.java`, `JwksController.java` | HTTP | 9 |
| `web/security/SecurityConfig.java` | Cadena de filtros | 9 |
| `web/ApiExceptionHandler.java` | `application/problem+json` | 9 |
| `application.yml`, `Dockerfile`, `kubernetes/`, `cloudbuild.yaml` | Configuración y despliegue | 10 |

---

### Task 1: Toolchain — Gradle 9.6.1, Boot 4.1.1, Java 25

El código actual no compila bajo Boot 4 (Jackson 3 cambia paquetes, Jakarta EE 11 cambia Hibernate). Esta tarea vacía `src/` y deja un esqueleto que compila y testea. El código anterior queda en el historial de git y en `origin/develop`.

**Files:**
- Modify: `gradle/wrapper/gradle-wrapper.properties`
- Modify: `build.gradle`
- Delete: `src/main/java/com/mobileamericas/authorization/**` (todo salvo `AuthorizationApplication.java`), `src/main/resources/application.yml`
- Create: `src/test/java/com/mobileamericas/authorization/ToolchainTest.java`

**Interfaces:**
- Consumes: nada.
- Produces: `./gradlew test` y `./gradlew integrationTest` como tareas válidas; *source set* `integrationTest` con sufijo de clase `*IT`.

- [ ] **Step 1: Subir el wrapper de Gradle**

```bash
./gradlew wrapper --gradle-version 9.6 --distribution-type bin
./gradlew --version
```

Esperado: `Gradle 9.6` y `JVM: 25.0.4`. Si el JVM no es 25, ejecuta `sdk use java 25.0.4-tem` antes.

- [ ] **Step 2: Escribir el test que falla**

`src/test/java/com/mobileamericas/authorization/ToolchainTest.java`:

```java
package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ToolchainTest {

    @Test
    void corre_sobre_java_25_o_superior() {
        assertThat(Runtime.version().feature()).isGreaterThanOrEqualTo(25);
    }

    @Test
    void los_records_del_dominio_son_utilizables() {
        record Prueba(String valor) {}
        assertThat(new Prueba("x").valor()).isEqualTo("x");
    }
}
```

- [ ] **Step 3: Verificar que falla**

Run: `./gradlew test`
Esperado: FALLA. La tarea `test` está comentada en `build.gradle`, así que no se ejecuta ningún test, o la compilación revienta porque el código viejo no es compatible con el toolchain nuevo.

- [ ] **Step 4: Vaciar el código antiguo**

```bash
cd /Users/difgar/Documents/sms-americas/develop/MA-Platform-Authorization
git rm -r --quiet src/main/java/com/mobileamericas/authorization/controllers \
                  src/main/java/com/mobileamericas/authorization/infrastructure \
                  src/main/java/com/mobileamericas/authorization/model \
                  src/main/java/com/mobileamericas/authorization/repositories \
                  src/main/java/com/mobileamericas/authorization/services \
                  src/main/java/com/mobileamericas/authorization/utils \
                  src/main/resources/application.yml
```

`AuthorizationApplication.java` se mantiene tal cual: no necesita cambios.

- [ ] **Step 5: Reescribir `build.gradle`**

```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '4.1.1'
    id 'io.spring.dependency-management' version '1.1.7'
}

group = 'com.mobileamericas'
version = '0.0.1-SNAPSHOT'

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

// Source set propio: los tests de integración levantan contenedores y no deben
// correr en cada './gradlew test'.
sourceSets {
    integrationTest {
        compileClasspath += sourceSets.main.output
        runtimeClasspath += sourceSets.main.output
    }
}

configurations {
    integrationTestImplementation.extendsFrom testImplementation
    integrationTestRuntimeOnly.extendsFrom testRuntimeOnly
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    implementation 'org.springframework.boot:spring-boot-starter-actuator'

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
}

tasks.named('test') {
    useJUnitPlatform()
    testLogging { events 'failed' }
}

tasks.register('integrationTest', Test) {
    description = 'Pruebas de integración contra MySQL y PostgreSQL reales.'
    group = 'verification'
    testClassesDirs = sourceSets.integrationTest.output.classesDirs
    classpath = sourceSets.integrationTest.runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter tasks.named('test')
    testLogging { events 'failed' }
}

tasks.named('check') {
    dependsOn tasks.named('integrationTest')
}

bootJar {
    archiveBaseName = 'ma-authorization'
}
```

El bloque `bootRun` del fichero anterior desaparece: inyectaba credenciales de desarrollo como propiedades de sistema. La configuración local pasa al perfil `dev` en la tarea 10.

- [ ] **Step 6: Verificar que pasa**

Run: `./gradlew test`
Esperado: PASA, 2 tests.

- [ ] **Step 7: Verificar que las dependencias de Boot 4 resuelven**

Run: `./gradlew dependencies --configuration runtimeClasspath | grep -E "spring-boot|jackson" | head -20`
Esperado: `org.springframework.boot:…:4.1.1` y Jackson en su versión 3.x.

Si algún *starter* no resuelve, consulta las notas de la versión de Boot 4 antes de inventar un nombre: la modularización renombró jars internos, no *starters*.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
build: migrar a Spring Boot 4.1.1, Java 25 y Gradle 9.6

Vacía el código anterior, que no compila bajo Jakarta EE 11 ni Jackson 3.
Queda accesible en el historial y en origin/develop.

Activa la tarea test, que estaba comentada, y añade un source set
integrationTest separado para que los contenedores no se levanten en
cada ejecución de './gradlew test'.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Dominio y expansión de comodines

Toda la lógica de permisos vive aquí, en records puros. Es la parte con más reglas y la que más barato es testear, así que va primero.

**Files:**
- Create: `src/main/java/com/mobileamericas/authorization/domain/Verb.java`
- Create: `src/main/java/com/mobileamericas/authorization/domain/Permission.java`
- Create: `src/main/java/com/mobileamericas/authorization/domain/App.java`
- Create: `src/main/java/com/mobileamericas/authorization/domain/Role.java`
- Create: `src/main/java/com/mobileamericas/authorization/domain/User.java`
- Create: `src/main/java/com/mobileamericas/authorization/domain/AccessGrant.java`
- Test: `src/test/java/com/mobileamericas/authorization/domain/PermissionTest.java`
- Test: `src/test/java/com/mobileamericas/authorization/domain/AccessGrantTest.java`

**Interfaces:**
- Consumes: nada del proyecto.
- Produces:
  - `Verb` — enum `CREAR, LEER, EDITAR, BORRAR`, con `String value()` y `static Verb of(String)`.
  - `Permission(String resource, String verb)` — `static Permission parse(String)`, `String asAuthority()`, `boolean isWildcard()`.
  - `App(UUID id, String name, String googleClientId, String url, boolean active)`.
  - `Role(UUID id, String name, UUID appId, Set<Permission> permissions)`.
  - `User(UUID id, String email, String fullName, boolean active, Set<Role> roles)`.
  - `AccessGrant(User user, App app, Set<String> roleNames, Set<String> authorities)` — `static AccessGrant of(User, App, Set<String> catalogoDeRecursos)`, `boolean isEmpty()`.

- [ ] **Step 1: Escribir los tests que fallan**

`src/test/java/com/mobileamericas/authorization/domain/PermissionTest.java`:

```java
package com.mobileamericas.authorization.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionTest {

    @Test
    void parsea_recurso_y_verbo() {
        var p = Permission.parse("campanas:editar");
        assertThat(p.resource()).isEqualTo("campanas");
        assertThat(p.verb()).isEqualTo("editar");
    }

    @Test
    void reconoce_los_comodines() {
        assertThat(Permission.parse("*:*").isWildcard()).isTrue();
        assertThat(Permission.parse("*:leer").isWildcard()).isTrue();
        assertThat(Permission.parse("campanas:*").isWildcard()).isTrue();
        assertThat(Permission.parse("campanas:leer").isWildcard()).isFalse();
    }

    @Test
    void rechaza_un_verbo_que_no_existe() {
        // 'escribir' fue descartado a propósito: agrupaba crear, editar y borrar,
        // y habría concedido borrado a roles que hoy no lo tienen.
        assertThatThrownBy(() -> Permission.parse("campanas:escribir"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("escribir");
    }

    @Test
    void rechaza_una_cadena_sin_dos_puntos() {
        assertThatThrownBy(() -> Permission.parse("campanas"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void se_serializa_como_autoridad() {
        assertThat(Permission.parse("redes:borrar").asAuthority()).isEqualTo("redes:borrar");
    }
}
```

`src/test/java/com/mobileamericas/authorization/domain/AccessGrantTest.java`:

```java
package com.mobileamericas.authorization.domain;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AccessGrantTest {

    private static final UUID APP_ID = UUID.randomUUID();
    private static final App APP =
            new App(APP_ID, "trafficflow", "cliente-123", "https://tf.example", true);
    private static final Set<String> CATALOGO = Set.of("campanas", "redes");

    private static User usuarioCon(Set<Permission> permisos) {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, permisos);
        return new User(UUID.randomUUID(), "p@ejemplo.com", "Persona", true, Set.of(rol));
    }

    @Test
    void expande_el_comodin_total_a_todos_los_recursos_por_todos_los_verbos() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:*"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactlyInAnyOrder(
                "campanas:crear", "campanas:leer", "campanas:editar", "campanas:borrar",
                "redes:crear", "redes:leer", "redes:editar", "redes:borrar");
    }

    @Test
    void expande_un_comodin_de_recurso_conservando_el_verbo() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:leer"))), APP, CATALOGO);

        assertThat(grant.authorities())
                .containsExactlyInAnyOrder("campanas:leer", "redes:leer");
    }

    @Test
    void expande_un_comodin_de_verbo_conservando_el_recurso() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("campanas:*"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactlyInAnyOrder(
                "campanas:crear", "campanas:leer", "campanas:editar", "campanas:borrar");
    }

    @Test
    void deja_intacto_un_permiso_concreto() {
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("redes:editar"))), APP, CATALOGO);

        assertThat(grant.authorities()).containsExactly("redes:editar");
    }

    @Test
    void ignora_los_roles_de_otras_aplicaciones() {
        var rolDeOtraApp = new Role(
                UUID.randomUUID(), "admin", UUID.randomUUID(), Set.of(Permission.parse("*:*")));
        var rolDeEsta = new Role(
                UUID.randomUUID(), "operador", APP_ID, Set.of(Permission.parse("redes:leer")));
        var usuario = new User(
                UUID.randomUUID(), "p@ejemplo.com", "Persona", true, Set.of(rolDeOtraApp, rolDeEsta));

        var grant = AccessGrant.of(usuario, APP, CATALOGO);

        assertThat(grant.authorities()).containsExactly("redes:leer");
        assertThat(grant.roleNames()).containsExactly("operador");
    }

    @Test
    void un_comodin_sobre_un_catalogo_vacio_no_concede_nada() {
        // El hueco que detectó la revisión del diseño: una app que solo declara
        // comodines dejaría a su administrador sin autoridades, en silencio.
        // Aquí se hace visible; la validación al alta vive en la tarea 4.
        var grant = AccessGrant.of(usuarioCon(Set.of(Permission.parse("*:*"))), APP, Set.of());

        assertThat(grant.authorities()).isEmpty();
        assertThat(grant.isEmpty()).isTrue();
    }

    @Test
    void un_usuario_inactivo_no_concede_nada() {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, Set.of(Permission.parse("*:*")));
        var inactivo = new User(UUID.randomUUID(), "p@ejemplo.com", "Persona", false, Set.of(rol));

        assertThat(AccessGrant.of(inactivo, APP, CATALOGO).isEmpty()).isTrue();
    }
}
```

- [ ] **Step 2: Verificar que fallan**

Run: `./gradlew test`
Esperado: FALLA al compilar — `Verb`, `Permission`, `App`, `Role`, `User` y `AccessGrant` no existen.

- [ ] **Step 3: Escribir el dominio**

`domain/Verb.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.Arrays;
import java.util.Locale;

/**
 * Los cuatro verbos del modelo de permisos.
 *
 * Son cuatro y no dos ("leer"/"escribir") por una razón concreta: el rol
 * support@admin del volcado de producción tiene view, read y update, pero NO
 * create ni delete. Agrupar los tres verbos de escritura le habría concedido un
 * permiso de borrado que hoy no tiene.
 */
public enum Verb {
    CREAR, LEER, EDITAR, BORRAR;

    public String value() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Verb of(String value) {
        return Arrays.stream(values())
                .filter(v -> v.value().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Verbo desconocido: '%s'. Los verbos son: crear, leer, editar, borrar."
                                .formatted(value)));
    }
}
```

`domain/Permission.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.Objects;

/** Un permiso es un par recurso+verbo. Cualquiera de los dos admite el comodín '*'. */
public record Permission(String resource, String verb) {

    public static final String ANY = "*";

    public Permission {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(verb, "verb");
        if (resource.isBlank()) {
            throw new IllegalArgumentException("El recurso no puede estar vacío.");
        }
        // Valida el verbo salvo que sea el comodín: 'campanas:escribir' debe fallar
        // aquí y no convertirse en una autoridad que nadie concede nunca.
        if (!ANY.equals(verb)) {
            Verb.of(verb);
        }
    }

    public static Permission parse(String texto) {
        Objects.requireNonNull(texto, "texto");
        int sep = texto.indexOf(':');
        if (sep < 0) {
            throw new IllegalArgumentException(
                    "Un permiso se escribe 'recurso:verbo'. Recibido: '%s'.".formatted(texto));
        }
        return new Permission(texto.substring(0, sep), texto.substring(sep + 1));
    }

    public boolean isWildcard() {
        return ANY.equals(resource) || ANY.equals(verb);
    }

    public String asAuthority() {
        return resource + ":" + verb;
    }
}
```

`domain/App.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.UUID;

public record App(UUID id, String name, String googleClientId, String url, boolean active) {}
```

`domain/Role.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.Set;
import java.util.UUID;

public record Role(UUID id, String name, UUID appId, Set<Permission> permissions) {

    public Role {
        permissions = Set.copyOf(permissions);
    }
}
```

`domain/User.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.Set;
import java.util.UUID;

public record User(UUID id, String email, String fullName, boolean active, Set<Role> roles) {

    public User {
        roles = Set.copyOf(roles);
    }
}
```

`domain/AccessGrant.java`:

```java
package com.mobileamericas.authorization.domain;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * Lo que un usuario concreto puede hacer en una app concreta, ya resuelto.
 *
 * Los comodines se expanden AQUÍ y no viajan nunca dentro del token: así el
 * token lleva siempre autoridades concretas y cualquier resource server estándar
 * funciona con hasAuthority() sin una línea de código propio.
 */
public record AccessGrant(User user, App app, Set<String> roleNames, Set<String> authorities) {

    public AccessGrant {
        roleNames = Set.copyOf(roleNames);
        authorities = Set.copyOf(authorities);
    }

    /**
     * @param resourceCatalogue recursos concretos declarados por la app. Si viene
     *                          vacío, un comodín no expande a nada: el grant queda
     *                          vacío en lugar de conceder de más.
     */
    public static AccessGrant of(User user, App app, Set<String> resourceCatalogue) {
        if (!user.active() || !app.active()) {
            return new AccessGrant(user, app, Set.of(), Set.of());
        }

        var rolesDeLaApp = user.roles().stream()
                .filter(rol -> rol.appId().equals(app.id()))
                .toList();

        var nombres = new TreeSet<String>();
        var autoridades = new LinkedHashSet<String>();

        for (var rol : rolesDeLaApp) {
            nombres.add(rol.name());
            for (var permiso : rol.permissions()) {
                autoridades.addAll(expandir(permiso, resourceCatalogue));
            }
        }
        return new AccessGrant(user, app, nombres, new TreeSet<>(autoridades));
    }

    private static Set<String> expandir(Permission permiso, Set<String> catalogo) {
        if (!permiso.isWildcard()) {
            return Set.of(permiso.asAuthority());
        }

        var recursos = Permission.ANY.equals(permiso.resource())
                ? catalogo
                : Set.of(permiso.resource());

        var verbos = Permission.ANY.equals(permiso.verb())
                ? Set.of(Verb.values())
                : Set.of(Verb.of(permiso.verb()));

        var resultado = new LinkedHashSet<String>();
        for (var recurso : recursos) {
            for (var verbo : verbos) {
                resultado.add(recurso + ":" + verbo.value());
            }
        }
        return resultado;
    }

    public boolean isEmpty() {
        return authorities.isEmpty();
    }
}
```

- [ ] **Step 4: Verificar que pasan**

Run: `./gradlew test`
Esperado: PASA. 13 tests (2 de la tarea 1, 5 de `PermissionTest`, 7 de `AccessGrantTest`).

- [ ] **Step 5: Verificar que el dominio no depende de ningún framework**

Run:
```bash
grep -rn "import jakarta\.\|import org.springframework\." src/main/java/com/mobileamericas/authorization/domain/ && echo "VIOLACIÓN" || echo "limpio"
```
Esperado: `limpio`.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/mobileamericas/authorization/domain src/test/java/com/mobileamericas/authorization/domain
git commit -m "$(cat <<'EOF'
feat: dominio de permisos con expansión de comodines

Los comodines se expanden al construir el AccessGrant y no viajan dentro
del token, de modo que cualquier resource server estándar funciona con
hasAuthority() sin código propio.

Cuatro verbos y no dos: support@admin tiene view, read y update pero no
create ni delete, y agrupar la escritura le habría dado borrado.

Un comodín sobre un catálogo vacío concede un conjunto vacío, que es el
hueco que detectó la revisión del diseño. Queda cubierto por un test.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Esquema portable y datos de producción

**Files:**
- Modify: `build.gradle` (Flyway, JPA, drivers, Testcontainers)
- Create: `src/main/resources/db/migration/V1__esquema.sql`
- Create: `src/main/resources/db/migration/V2__datos_iniciales.sql`
- Create: `src/integrationTest/java/com/mobileamericas/authorization/BaseIT.java`
- Create: `src/integrationTest/java/com/mobileamericas/authorization/MigracionMySqlIT.java`
- Create: `src/integrationTest/java/com/mobileamericas/authorization/MigracionPostgresIT.java`
- Create: `src/integrationTest/resources/application.yml`

**Interfaces:**
- Consumes: nada del dominio.
- Produces: `BaseIT` — clase base con `@SpringBootTest` y `JdbcClient` inyectado, de la que heredan todas las pruebas de integración; cada motor la extiende añadiendo su contenedor con `@ServiceConnection`.

- [ ] **Step 1: Añadir dependencias**

En `build.gradle`, dentro de `dependencies`:

```groovy
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.flywaydb:flyway-core'
    runtimeOnly 'org.flywaydb:flyway-mysql'
    runtimeOnly 'org.flywaydb:flyway-database-postgresql'
    runtimeOnly 'com.mysql:mysql-connector-j'
    runtimeOnly 'org.postgresql:postgresql'

    integrationTestImplementation 'org.springframework.boot:spring-boot-testcontainers'
    integrationTestImplementation 'org.testcontainers:junit-jupiter'
    integrationTestImplementation 'org.testcontainers:mysql'
    integrationTestImplementation 'org.testcontainers:postgresql'
```

- [ ] **Step 2: Escribir los tests que fallan**

`src/integrationTest/resources/application.yml`:

```yaml
spring:
  jpa:
    hibernate.ddl-auto: validate   # Flyway manda; Hibernate solo comprueba
    open-in-view: false
  flyway:
    enabled: true
```

`src/integrationTest/java/com/mobileamericas/authorization/BaseIT.java`:

```java
package com.mobileamericas.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base de toda prueba de integración. Cada motor la extiende con su contenedor.
 *
 * La misma suite se ejecuta contra MySQL y contra PostgreSQL: es lo que convierte
 * "agnóstico del motor" en un hecho que verifica el build y no en una promesa.
 */
@SpringBootTest
public abstract class BaseIT {

    @Autowired
    protected JdbcClient jdbc;

    private long contar(String tabla) {
        return jdbc.sql("SELECT count(*) FROM " + tabla).query(Long.class).single();
    }

    @Test
    void las_migraciones_crean_las_ocho_tablas() {
        for (var tabla : new String[]{
                "auth_app", "auth_permission", "auth_role", "auth_user",
                "auth_user_role", "auth_role_permission",
                "auth_refresh_token", "auth_audit"}) {
            assertThat(contar(tabla)).as("tabla %s", tabla).isGreaterThanOrEqualTo(0L);
        }
    }

    @Test
    void reproduce_el_volcado_de_produccion() {
        assertThat(contar("auth_app")).isEqualTo(2L);
        assertThat(contar("auth_user")).isEqualTo(2L);
        assertThat(contar("auth_role")).isEqualTo(5L);
        assertThat(contar("auth_user_role")).isEqualTo(4L);
    }

    @Test
    void support_conserva_exactamente_sus_privilegios() {
        // view, read, update -> *:leer y *:editar. Ni crear ni borrar.
        var permisos = jdbc.sql("""
                        SELECT p.resource || ':' || p.verb FROM auth_permission p
                          JOIN auth_role_permission rp ON rp.permission_id = p.id
                          JOIN auth_role r ON r.id = rp.role_id
                          JOIN auth_app a ON a.id = r.app_id
                         WHERE r.name = 'support' AND a.name = 'admin'
                        """.replace("||", concatenador()))
                .query(String.class).list();

        assertThat(permisos).containsExactlyInAnyOrder("*:leer", "*:editar");
    }

    @Test
    void cada_app_declara_un_catalogo_de_recursos_concretos() {
        // Sin recursos concretos, '*:*' expandiría a nada (ver AccessGrantTest).
        var apps = jdbc.sql("""
                        SELECT a.name FROM auth_app a
                         WHERE NOT EXISTS (
                           SELECT 1 FROM auth_permission p
                            WHERE p.app_id = a.id AND p.resource <> '*')
                        """).query(String.class).list();

        assertThat(apps).as("apps sin catálogo de recursos").isEmpty();
    }

    /** MySQL no tiene el operador '||' salvo en modo ANSI; usa CONCAT. */
    protected abstract String concatenador();
}
```

`src/integrationTest/java/com/mobileamericas/authorization/MigracionMySqlIT.java`:

```java
package com.mobileamericas.authorization;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class MigracionMySqlIT extends BaseIT {

    @Container
    @ServiceConnection
    static MySQLContainer<?> db = new MySQLContainer<>("mysql:8.4");

    @Override
    protected String concatenador() {
        return "), ':', (";   // SELECT CONCAT(p.resource, ':', p.verb)
    }
}
```

> Nota para quien implemente: el truco del `concatenador()` con paréntesis es
> frágil. Si al ejecutar da problemas, sustituye la consulta de
> `support_conserva_exactamente_sus_privilegios` por dos columnas
> (`SELECT p.resource, p.verb`) y compón la cadena en Java. Es más claro y
> elimina la diferencia de dialecto en la prueba.

`src/integrationTest/java/com/mobileamericas/authorization/MigracionPostgresIT.java`:

```java
package com.mobileamericas.authorization;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class MigracionPostgresIT extends BaseIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:17");

    @Override
    protected String concatenador() {
        return "||";
    }
}
```

- [ ] **Step 3: Verificar que fallan**

Run: `./gradlew integrationTest`
Esperado: FALLA — no existen las migraciones, así que no hay tablas.

- [ ] **Step 4: Escribir `V1__esquema.sql`**

`src/main/resources/db/migration/V1__esquema.sql`:

```sql
-- Un único juego de migraciones para MySQL 8 y PostgreSQL 17.
--
-- Solo se usan tipos que ambos motores aceptan con sintaxis idéntica:
-- VARCHAR, BIGINT, BOOLEAN, TIMESTAMP(6), TEXT.
--
-- Prohibidos aquí: AUTO_INCREMENT, GENERATED AS IDENTITY, JSON/jsonb, ENUM,
-- DEFAULT CHARSET= y ENGINE=. Las claves primarias son UUID generados en la
-- aplicación, que es lo que elimina el único constructo sin sintaxis común.
--
-- El juego de caracteres se fija al crear la base de datos (utf8mb4 en MySQL),
-- no por tabla: 'DEFAULT CHARSET=' rompería en PostgreSQL.

CREATE TABLE auth_app (
    id               VARCHAR(36)  NOT NULL,
    name             VARCHAR(100) NOT NULL,
    google_client_id VARCHAR(255) NOT NULL,
    url              VARCHAR(255),
    active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMP(6) NOT NULL,
    updated_at       TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_app PRIMARY KEY (id),
    CONSTRAINT uk_auth_app_name UNIQUE (name),
    CONSTRAINT uk_auth_app_google_client_id UNIQUE (google_client_id)
);

CREATE TABLE auth_permission (
    id          VARCHAR(36)  NOT NULL,
    app_id      VARCHAR(36)  NOT NULL,
    resource    VARCHAR(100) NOT NULL,
    verb        VARCHAR(20)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_permission PRIMARY KEY (id),
    CONSTRAINT uk_auth_permission UNIQUE (app_id, resource, verb),
    CONSTRAINT fk_auth_permission_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE TABLE auth_role (
    id          VARCHAR(36)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    app_id      VARCHAR(36)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP(6) NOT NULL,
    updated_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_role PRIMARY KEY (id),
    CONSTRAINT uk_auth_role_name_app UNIQUE (name, app_id),
    CONSTRAINT fk_auth_role_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE TABLE auth_user (
    id         VARCHAR(36)  NOT NULL,
    email      VARCHAR(320) NOT NULL,
    full_name  VARCHAR(255),
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_user PRIMARY KEY (id),
    CONSTRAINT uk_auth_user_email UNIQUE (email)
);

CREATE TABLE auth_user_role (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    CONSTRAINT pk_auth_user_role PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_auth_user_role_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_auth_user_role_role FOREIGN KEY (role_id) REFERENCES auth_role (id)
);

CREATE TABLE auth_role_permission (
    role_id       VARCHAR(36) NOT NULL,
    permission_id VARCHAR(36) NOT NULL,
    CONSTRAINT pk_auth_role_permission PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_auth_rp_role FOREIGN KEY (role_id) REFERENCES auth_role (id),
    CONSTRAINT fk_auth_rp_permission FOREIGN KEY (permission_id) REFERENCES auth_permission (id)
);

-- Se guarda el SHA-256 del token, nunca el token: un volcado de esta tabla no
-- permite suplantar a nadie. family_id agrupa las rotaciones sucesivas de una
-- misma sesión, para poder revocarlas todas si una se reutiliza.
CREATE TABLE auth_refresh_token (
    id         VARCHAR(36)  NOT NULL,
    user_id    VARCHAR(36)  NOT NULL,
    app_id     VARCHAR(36)  NOT NULL,
    token_hash VARCHAR(64)  NOT NULL,
    family_id  VARCHAR(36)  NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    used_at    TIMESTAMP(6),
    revoked_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_refresh_token PRIMARY KEY (id),
    CONSTRAINT uk_auth_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_auth_rt_user FOREIGN KEY (user_id) REFERENCES auth_user (id),
    CONSTRAINT fk_auth_rt_app FOREIGN KEY (app_id) REFERENCES auth_app (id)
);

CREATE INDEX ix_auth_refresh_token_family ON auth_refresh_token (family_id);

-- payload es TEXT y no JSON/jsonb a propósito: MySQL tiene JSON y PostgreSQL
-- tiene jsonb, y no son la misma sintaxis. Consultar dentro del payload sería
-- una migración específica por motor, consciente, no una sorpresa.
CREATE TABLE auth_audit (
    id          VARCHAR(36)  NOT NULL,
    actor_email VARCHAR(320) NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    entity      VARCHAR(50)  NOT NULL,
    entity_id   VARCHAR(36),
    payload     TEXT,
    created_at  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_auth_audit PRIMARY KEY (id)
);

CREATE INDEX ix_auth_audit_created ON auth_audit (created_at);
```

- [ ] **Step 5: Escribir `V2__datos_iniciales.sql`**

`src/main/resources/db/migration/V2__datos_iniciales.sql`:

```sql
-- Reproduce el volcado de producción del 2026-09-16 (2 apps, 5 roles, 2
-- usuarios, 4 asignaciones usuario->rol) con equivalencia EXACTA de privilegios.
--
-- Los permisos antiguos eran verbos sueltos: view, read, create, update, delete.
-- view y read eran redundantes y colapsan en 'leer'. create, update y delete se
-- mantienen distinguibles como crear, editar y borrar: agruparlos en un único
-- 'escribir' le habría dado a support@admin un permiso de borrado que no tiene.
--
-- Los UUID van fijos y no generados: una migración debe producir el mismo
-- resultado en cada entorno donde se aplique.
--
-- Los google_client_id son marcadores. Se sustituyen por los reales con una
-- migración posterior o por el CRUD de la fase 2, NUNCA con el valor en git.

INSERT INTO auth_app (id, name, google_client_id, url, active, created_at, updated_at) VALUES
 ('a0000000-0000-4000-8000-000000000001', 'admin', 'PENDIENTE-admin', 'https://admin.mobile-americas.com', TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('a0000000-0000-4000-8000-000000000002', 'fgf',   'PENDIENTE-fgf',   'https://fgf.mobile-americas.com',   TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- Catálogo de recursos concretos. Es obligatorio: sin él, '*:*' expande a nada.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'apps',     'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000001', 'apps',     'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000003', 'a0000000-0000-4000-8000-000000000001', 'apps',     'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000004', 'a0000000-0000-4000-8000-000000000001', 'apps',     'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000005', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000006', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000007', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000008', 'a0000000-0000-4000-8000-000000000001', 'usuarios', 'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000009', 'a0000000-0000-4000-8000-000000000001', 'roles',    'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000a', 'a0000000-0000-4000-8000-000000000001', 'roles',    'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000b', 'a0000000-0000-4000-8000-000000000001', 'roles',    'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-00000000000c', 'a0000000-0000-4000-8000-000000000001', 'roles',    'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000010', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'crear',  NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000011', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000012', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-000000000013', 'a0000000-0000-4000-8000-000000000002', 'usuarios', 'borrar', NULL, TIMESTAMP '2026-09-16 00:00:00');

-- Comodines. Se expanden contra el catálogo de arriba al emitir el token.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-0000000000f1', 'a0000000-0000-4000-8000-000000000001', '*', '*',      'Todo en admin', TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f2', 'a0000000-0000-4000-8000-000000000001', '*', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f3', 'a0000000-0000-4000-8000-000000000001', '*', 'editar', NULL, TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f4', 'a0000000-0000-4000-8000-000000000002', '*', '*',      'Todo en fgf',   TIMESTAMP '2026-09-16 00:00:00'),
 ('b0000000-0000-4000-8000-0000000000f5', 'a0000000-0000-4000-8000-000000000002', '*', 'leer',   NULL, TIMESTAMP '2026-09-16 00:00:00');

INSERT INTO auth_role (id, name, app_id, description, created_at, updated_at) VALUES
 ('c0000000-0000-4000-8000-000000000001', 'admin',   'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000002', 'support', 'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000003', 'analyst', 'a0000000-0000-4000-8000-000000000001', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000004', 'admin',   'a0000000-0000-4000-8000-000000000002', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('c0000000-0000-4000-8000-000000000005', 'user',    'a0000000-0000-4000-8000-000000000002', NULL, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- admin@admin: view read create update delete -> *:*
-- support@admin: view read update             -> *:leer, *:editar
-- analyst@admin: view read                    -> *:leer
-- admin@fgf: view read create update delete   -> *:*
-- user@fgf: view                              -> *:leer
INSERT INTO auth_role_permission (role_id, permission_id) VALUES
 ('c0000000-0000-4000-8000-000000000001', 'b0000000-0000-4000-8000-0000000000f1'),
 ('c0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-0000000000f2'),
 ('c0000000-0000-4000-8000-000000000002', 'b0000000-0000-4000-8000-0000000000f3'),
 ('c0000000-0000-4000-8000-000000000003', 'b0000000-0000-4000-8000-0000000000f2'),
 ('c0000000-0000-4000-8000-000000000004', 'b0000000-0000-4000-8000-0000000000f4'),
 ('c0000000-0000-4000-8000-000000000005', 'b0000000-0000-4000-8000-0000000000f5');

-- Los dos usuarios del volcado. Los emails reales se ponen con una migración
-- posterior o por el CRUD de la fase 2; aquí van marcadores para no meter datos
-- personales en git.
INSERT INTO auth_user (id, email, full_name, active, created_at, updated_at) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'usuario1@pendiente.local', NULL, TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00'),
 ('d0000000-0000-4000-8000-000000000002', 'usuario2@pendiente.local', NULL, TRUE, TIMESTAMP '2026-09-16 00:00:00', TIMESTAMP '2026-09-16 00:00:00');

-- usuario1 -> admin@admin, user@fgf   ·   usuario2 -> analyst@admin, admin@fgf
INSERT INTO auth_user_role (user_id, role_id) VALUES
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000005'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000003'),
 ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000004');
```

- [ ] **Step 6: Verificar que pasan en los dos motores**

Run: `./gradlew integrationTest`
Esperado: PASA, 8 tests (4 × 2 motores). Docker debe estar arrancado.

Si `TIMESTAMP '…'` diera problemas en MySQL, sustitúyelo por el literal desnudo `'2026-09-16 00:00:00'`, que ambos motores aceptan en un `INSERT`.

- [ ] **Step 7: Commit**

```bash
git add build.gradle src/main/resources/db src/integrationTest
git commit -m "$(cat <<'EOF'
feat: esquema portable y datos del volcado de producción

Un único juego de migraciones para MySQL 8 y PostgreSQL 17. Las claves
primarias son UUID generados en la aplicación, que elimina el único
constructo sin sintaxis común entre los dos motores: el autoincremento.

La suite de integración se ejecuta contra los dos, que es lo que convierte
"agnóstico del motor" en algo que verifica el build.

Los privilegios de los cinco roles se conservan exactamente; hay un test
que lo comprueba para support@admin, el único con un subconjunto no trivial.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Adaptador de persistencia

**Files:**
- Create: `application/port/AppRepository.java`, `UserRepository.java`
- Create: `adapter/persistence/AppEntity.java`, `PermissionEntity.java`, `RoleEntity.java`, `UserEntity.java`
- Create: `adapter/persistence/DomainMapper.java`
- Create: `adapter/persistence/JpaAppRepository.java`, `JpaUserRepository.java`
- Create: `adapter/persistence/AppRepositoryAdapter.java`, `UserRepositoryAdapter.java`
- Test: `src/integrationTest/java/com/mobileamericas/authorization/adapter/persistence/RepositoriosIT.java` (+ subclases por motor)

**Interfaces:**
- Consumes: `domain.App`, `domain.User`, `domain.Role`, `domain.Permission` (tarea 2).
- Produces:
  - `AppRepository` — `Optional<App> findByGoogleClientId(String)`, `Optional<App> findByName(String)`, `Set<String> resourceCatalogue(UUID appId)`.
  - `UserRepository` — `Optional<User> findByEmail(String)`, `Optional<User> findById(UUID)`.

- [ ] **Step 1: Escribir el test que falla**

`src/integrationTest/java/com/mobileamericas/authorization/adapter/persistence/RepositoriosIT.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.BaseIT;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class RepositoriosIT extends BaseIT {

    @Autowired AppRepository apps;
    @Autowired UserRepository usuarios;

    @Test
    void encuentra_la_app_por_su_client_id_de_google() {
        var app = apps.findByGoogleClientId("PENDIENTE-admin");

        assertThat(app).isPresent();
        assertThat(app.get().name()).isEqualTo("admin");
    }

    @Test
    void no_encuentra_un_client_id_desconocido() {
        assertThat(apps.findByGoogleClientId("no-existe")).isEmpty();
    }

    @Test
    void el_catalogo_de_recursos_excluye_los_comodines() {
        var app = apps.findByName("admin").orElseThrow();

        assertThat(apps.resourceCatalogue(app.id()))
                .containsExactlyInAnyOrder("apps", "usuarios", "roles")
                .doesNotContain("*");
    }

    @Test
    void carga_el_usuario_con_sus_roles_y_permisos() {
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        assertThat(usuario.roles()).hasSize(2);
        assertThat(usuario.roles()).extracting("name")
                .containsExactlyInAnyOrder("admin", "user");
    }

    @Test
    void el_grant_de_usuario1_en_admin_expande_a_las_doce_autoridades() {
        var app = apps.findByName("admin").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));

        // 3 recursos x 4 verbos: el rol admin tiene '*:*'
        assertThat(grant.authorities()).hasSize(12)
                .contains("apps:borrar", "usuarios:crear", "roles:editar");
        assertThat(grant.roleNames()).containsExactly("admin");
    }

    @Test
    void el_grant_de_usuario1_en_fgf_solo_tiene_lectura() {
        var fgf = apps.findByName("fgf").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        var grant = AccessGrant.of(usuario, fgf, apps.resourceCatalogue(fgf.id()));

        assertThat(grant.authorities()).containsExactly("usuarios:leer");
    }
}
```

Y las dos subclases, que solo aportan el contenedor:

`RepositoriosMySqlIT.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class RepositoriosMySqlIT extends RepositoriosIT {

    @Container
    @ServiceConnection
    static MySQLContainer<?> db = new MySQLContainer<>("mysql:8.4");

    @Override
    protected String concatenador() {
        return "), ':', (";
    }
}
```

`RepositoriosPostgresIT.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class RepositoriosPostgresIT extends RepositoriosIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:17");

    @Override
    protected String concatenador() {
        return "||";
    }
}
```

- [ ] **Step 2: Verificar que falla**

Run: `./gradlew integrationTest`
Esperado: FALLA al compilar — `AppRepository` y `UserRepository` no existen.

- [ ] **Step 3: Escribir los puertos**

`application/port/AppRepository.java`:

```java
package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.App;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface AppRepository {

    Optional<App> findByGoogleClientId(String googleClientId);

    Optional<App> findByName(String name);

    /** Lo usa refresh(): la familia del refresh token guarda el id, no el nombre. */
    Optional<App> findById(UUID id);

    /** Recursos concretos declarados por la app. Nunca incluye el comodín '*'. */
    Set<String> resourceCatalogue(UUID appId);
}
```

`application/port/UserRepository.java`:

```java
package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository {

    Optional<User> findByEmail(String email);

    Optional<User> findById(UUID id);
}
```

- [ ] **Step 4: Escribir las entidades JPA**

Quedan encerradas en `adapter/persistence` y no salen de ahí: el dominio es lo
que cruza la frontera.

`adapter/persistence/AppEntity.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_app")
class AppEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 100)
    String name;

    @Column(name = "google_client_id", nullable = false)
    String googleClientId;

    String url;

    @Column(nullable = false)
    boolean active;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected AppEntity() {}
}
```

`adapter/persistence/PermissionEntity.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_permission")
class PermissionEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    @Column(nullable = false, length = 100)
    String resource;

    @Column(nullable = false, length = 20)
    String verb;

    String description;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    protected PermissionEntity() {}
}
```

`adapter/persistence/RoleEntity.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "auth_role")
class RoleEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 100)
    String name;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    String description;

    // EAGER aquí es deliberado y acotado: un rol tiene unos pocos permisos y
    // siempre se necesitan juntos. No es el EAGER global del código anterior,
    // que existía sólo para que el grafo sobreviviera fuera de la transacción.
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "auth_role_permission",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    Set<PermissionEntity> permissions;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected RoleEntity() {}
}
```

`adapter/persistence/UserEntity.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "auth_user")
class UserEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(nullable = false, length = 320)
    String email;

    @Column(name = "full_name")
    String fullName;

    @Column(nullable = false)
    boolean active;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "auth_user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    Set<RoleEntity> roles;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    Instant updatedAt;

    protected UserEntity() {}
}
```

- [ ] **Step 5: Escribir el mapeador y los adaptadores**

`adapter/persistence/DomainMapper.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;

import java.util.UUID;
import java.util.stream.Collectors;

/** El único punto donde una entidad JPA se convierte en dominio. */
final class DomainMapper {

    private DomainMapper() {}

    static App toDomain(AppEntity e) {
        return new App(UUID.fromString(e.id), e.name, e.googleClientId, e.url, e.active);
    }

    static User toDomain(UserEntity e) {
        var roles = e.roles.stream().map(DomainMapper::toDomain).collect(Collectors.toSet());
        return new User(UUID.fromString(e.id), e.email, e.fullName, e.active, roles);
    }

    static Role toDomain(RoleEntity e) {
        var permisos = e.permissions.stream()
                .map(p -> new Permission(p.resource, p.verb))
                .collect(Collectors.toSet());
        return new Role(UUID.fromString(e.id), e.name, UUID.fromString(e.appId), permisos);
    }
}
```

`adapter/persistence/JpaAppRepository.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

interface JpaAppRepository extends JpaRepository<AppEntity, String> {

    Optional<AppEntity> findByGoogleClientId(String googleClientId);

    Optional<AppEntity> findByName(String name);

    @Query("""
            SELECT DISTINCT p.resource FROM PermissionEntity p
             WHERE p.appId = :appId AND p.resource <> '*'
            """)
    List<String> findResourcesByAppId(@Param("appId") String appId);
}
```

`adapter/persistence/AppRepositoryAdapter.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.domain.App;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
@Transactional(readOnly = true)
class AppRepositoryAdapter implements AppRepository {

    private final JpaAppRepository jpa;

    AppRepositoryAdapter(JpaAppRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    public Optional<App> findByGoogleClientId(String googleClientId) {
        return jpa.findByGoogleClientId(googleClientId).map(DomainMapper::toDomain);
    }

    @Override
    public Optional<App> findByName(String name) {
        return jpa.findByName(name).map(DomainMapper::toDomain);
    }

    @Override
    public Optional<App> findById(UUID id) {
        return jpa.findById(id.toString()).map(DomainMapper::toDomain);
    }

    @Override
    public Set<String> resourceCatalogue(UUID appId) {
        return Set.copyOf(jpa.findResourcesByAppId(appId.toString()));
    }
}
```

`adapter/persistence/JpaUserRepository.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

interface JpaUserRepository extends JpaRepository<UserEntity, String> {

    Optional<UserEntity> findByEmail(String email);
}
```

`adapter/persistence/UserRepositoryAdapter.java`:

```java
package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.User;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
@Transactional(readOnly = true)
class UserRepositoryAdapter implements UserRepository {

    private final JpaUserRepository jpa;

    UserRepositoryAdapter(JpaUserRepository jpa) {
        this.jpa = jpa;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return jpa.findByEmail(email).map(DomainMapper::toDomain);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpa.findById(id.toString()).map(DomainMapper::toDomain);
    }
}
```

- [ ] **Step 6: Verificar que pasan en los dos motores**

Run: `./gradlew integrationTest`
Esperado: PASA, 20 tests (4 de migración + 6 de repositorios, × 2 motores).

- [ ] **Step 7: Verificar que las entidades JPA no salen del adaptador**

Run:
```bash
grep -rn "Entity" src/main/java/com/mobileamericas/authorization/application \
                   src/main/java/com/mobileamericas/authorization/domain \
  && echo "VIOLACIÓN" || echo "limpio"
```
Esperado: `limpio`. Las clases entidad son *package-private* precisamente para
que esto no pueda ocurrir por descuido.

- [ ] **Step 8: Commit**

```bash
git add src/main/java src/integrationTest
git commit -m "$(cat <<'EOF'
feat: adaptador de persistencia con el dominio como frontera

Las entidades JPA son package-private y no salen de adapter/persistence:
lo que cruza la frontera son los records del dominio. Ese era el
acoplamiento real al motor en el código anterior, donde UserEntity era la
moneda de cambio de toda la aplicación y obligaba a un EAGER global.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Emisión de tokens RS256 y JWKS

**Files:**
- Modify: `build.gradle` (`spring-security-oauth2-jose`)
- Create: `application/port/TokenIssuer.java`
- Create: `adapter/token/JwtKeys.java`
- Create: `adapter/token/JwtProperties.java`
- Create: `adapter/token/RsaTokenIssuer.java`
- Test: `src/test/java/com/mobileamericas/authorization/adapter/token/RsaTokenIssuerTest.java`

**Interfaces:**
- Consumes: `domain.AccessGrant` (tarea 2).
- Produces:
  - `TokenIssuer` — `String issueAccessToken(AccessGrant)`, `Duration accessTokenTtl()`.
  - `JwtKeys` — `JWKSource<SecurityContext> jwkSource()`, `Map<String,Object> publicJwks()`, `String activeKeyId()`.

- [ ] **Step 1: Añadir la dependencia**

En `build.gradle`:

```groovy
    implementation 'org.springframework.security:spring-security-oauth2-jose'
```

- [ ] **Step 2: Escribir el test que falla**

`src/test/java/com/mobileamericas/authorization/adapter/token/RsaTokenIssuerTest.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.domain.AccessGrant;
import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.Permission;
import com.mobileamericas.authorization.domain.Role;
import com.mobileamericas.authorization.domain.User;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaTokenIssuerTest {

    private static final String EMISOR = "https://auth.mobile-americas.com";
    private static final UUID APP_ID = UUID.randomUUID();

    private RSAKey clave;
    private RsaTokenIssuer emisor;

    @BeforeEach
    void preparar() throws Exception {
        // Claves generadas en el test: cero dependencia de Google y del entorno.
        clave = new RSAKeyGenerator(2048).keyID("test-2026-09").generate();
        var keys = JwtKeys.forTesting(clave);
        emisor = new RsaTokenIssuer(keys, new JwtProperties(EMISOR, Duration.ofMinutes(15), Duration.ofHours(12)));
    }

    private AccessGrant grant() {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID,
                Set.of(Permission.parse("campanas:leer"), Permission.parse("campanas:editar")));
        var usuario = new User(
                UUID.fromString("d0000000-0000-4000-8000-000000000001"),
                "persona@ejemplo.com", "Persona", true, Set.of(rol));
        var app = new App(APP_ID, "trafficflow", "cliente-123", null, true);
        return AccessGrant.of(usuario, app, Set.of("campanas"));
    }

    private JwtDecoder decodificador() {
        return NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
    }

    @Test
    void el_token_se_verifica_con_la_clave_publica() {
        var jwt = decodificador().decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getSubject()).isEqualTo("d0000000-0000-4000-8000-000000000001");
        assertThat(jwt.getIssuer()).hasToString(EMISOR);
        assertThat(jwt.getAudience()).containsExactly("trafficflow");
    }

    @Test
    void el_sub_es_el_uuid_y_no_el_email() {
        // El email puede cambiar; el identificador del sujeto debe ser estable.
        var jwt = decodificador().decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getSubject()).doesNotContain("@");
        assertThat(jwt.getClaimAsString("email")).isEqualTo("persona@ejemplo.com");
    }

    @Test
    void lleva_las_autoridades_ya_expandidas() {
        var jwt = decodificador().decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getClaimAsStringList("permissions"))
                .containsExactlyInAnyOrder("campanas:leer", "campanas:editar")
                .doesNotContain("*:*");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("operador");
    }

    @Test
    void la_cabecera_lleva_el_kid_para_poder_rotar() {
        var jwt = decodificador().decode(emisor.issueAccessToken(grant()));

        assertThat(jwt.getHeaders()).containsEntry("kid", "test-2026-09");
        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256");
    }

    @Test
    void un_resource_server_de_otra_app_rechaza_el_token() {
        // El aislamiento entre aplicaciones (§8 del spec). Un token emitido para
        // 'trafficflow' no debe valer contra un servicio configurado para 'admin',
        // y eso lo hace el propio resource server, sin código nuestro.
        var token = emisor.issueAccessToken(grant());

        var comoTrafficflow = NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
        comoTrafficflow.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), new JwtClaimValidator<List<String>>(
                        "aud", aud -> aud != null && aud.contains("trafficflow"))));
        assertThat(comoTrafficflow.decode(token)).isNotNull();

        var comoAdmin = NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
        comoAdmin.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), new JwtClaimValidator<List<String>>(
                        "aud", aud -> aud != null && aud.contains("admin"))));

        assertThatThrownBy(() -> comoAdmin.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void caduca_a_los_quince_minutos_y_lleva_jti() {
        var jwt = decodificador().decode(emisor.issueAccessToken(grant()));

        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt()))
                .isEqualTo(Duration.ofMinutes(15));
        assertThat(jwt.getId()).isNotBlank();
    }

    @Test
    void el_jwks_publico_no_contiene_la_clave_privada() {
        var jwks = JwtKeys.forTesting(clave).publicJwks().toString();

        // 'd' es el exponente privado en una JWK RSA; 'p' y 'q' los factores.
        assertThat(jwks).contains("\"n\":").contains("\"e\":").contains("test-2026-09");
        assertThat(jwks).doesNotContain("\"d\":").doesNotContain("\"p\":").doesNotContain("\"q\":");
    }
}
```

- [ ] **Step 3: Verificar que falla**

Run: `./gradlew test --tests '*RsaTokenIssuerTest*'`
Esperado: FALLA al compilar — no existen `JwtKeys`, `JwtProperties` ni `RsaTokenIssuer`.

- [ ] **Step 4: Escribir el puerto y la configuración**

`application/port/TokenIssuer.java`:

```java
package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.AccessGrant;

import java.time.Duration;

public interface TokenIssuer {

    String issueAccessToken(AccessGrant grant);

    Duration accessTokenTtl();
}
```

`adapter/token/JwtProperties.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "authorization.jwt")
public record JwtProperties(String issuer, Duration accessTtl, Duration refreshTtl) {

    public JwtProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("authorization.jwt.issuer es obligatorio.");
        }
        accessTtl = accessTtl == null ? Duration.ofMinutes(15) : accessTtl;
        refreshTtl = refreshTtl == null ? Duration.ofHours(12) : refreshTtl;
    }
}
```

- [ ] **Step 5: Escribir `JwtKeys`**

`adapter/token/JwtKeys.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * El conjunto de claves de firma.
 *
 * Admite varias a la vez para poder rotar sin invalidar nada: se añade la nueva
 * al JWKS, se empieza a firmar con ella, y la vieja se retira cuando expira el
 * último token que firmó (15 minutos). La PRIMERA de la lista es la activa.
 */
public final class JwtKeys {

    private final List<RSAKey> keys;

    private JwtKeys(List<RSAKey> keys) {
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Hace falta al menos una clave de firma.");
        }
        this.keys = List.copyOf(keys);
    }

    /** Desde JWK en JSON. La primera es la activa. */
    public static JwtKeys fromJson(List<String> jwksJson) {
        return new JwtKeys(jwksJson.stream().map(JwtKeys::parse).toList());
    }

    public static JwtKeys forTesting(RSAKey... claves) {
        return new JwtKeys(List.of(claves));
    }

    private static RSAKey parse(String json) {
        try {
            var key = RSAKey.parse(json);
            if (!key.isPrivate()) {
                throw new IllegalArgumentException("La clave " + key.getKeyID() + " no tiene parte privada.");
            }
            return key;
        } catch (ParseException e) {
            throw new IllegalArgumentException("Clave de firma ilegible.", e);
        }
    }

    public String activeKeyId() {
        return keys.getFirst().getKeyID();
    }

    RSAKey activeKey() {
        return keys.getFirst();
    }

    /** La pública de la clave activa, para validar nuestros propios tokens. */
    public RSAPublicKey activePublicKey() {
        try {
            return activeKey().toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("La clave activa no expone su parte pública.", e);
        }
    }

    public JWKSource<SecurityContext> jwkSource() {
        return new ImmutableJWKSet<>(new JWKSet(List.copyOf(keys)));
    }

    /**
     * El conjunto público. {@code toPublicJWKSet()} descarta la parte privada:
     * es lo que impide que 'd', 'p' y 'q' salgan por el endpoint.
     */
    public Map<String, Object> publicJwks() {
        return new JWKSet(List.copyOf(keys)).toPublicJWKSet().toJSONObject();
    }
}
```

- [ ] **Step 6: Escribir `RsaTokenIssuer`**

`adapter/token/RsaTokenIssuer.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.TokenIssuer;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class RsaTokenIssuer implements TokenIssuer {

    private final JwtKeys keys;
    private final JwtProperties props;
    private final JwtEncoder encoder;

    public RsaTokenIssuer(JwtKeys keys, JwtProperties props) {
        this.keys = keys;
        this.props = props;
        this.encoder = new NimbusJwtEncoder(keys.jwkSource());
    }

    @Override
    public String issueAccessToken(AccessGrant grant) {
        var ahora = Instant.now();

        var claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                // El UUID, no el email: el email puede cambiar y 'sub' debe ser estable.
                .subject(grant.user().id().toString())
                // La app. Un token de 'admin' no vale contra 'trafficflow': lo
                // rechaza el propio resource server, sin código nuestro.
                .audience(List.of(grant.app().name()))
                .issuedAt(ahora)
                .expiresAt(ahora.plus(props.accessTtl()))
                .id(UUID.randomUUID().toString())
                .claim("email", grant.user().email())
                .claim("name", grant.user().fullName())
                .claim("roles", List.copyOf(grant.roleNames()))
                // Autoridades concretas: los comodines ya se expandieron en el dominio.
                .claim("permissions", List.copyOf(grant.authorities()))
                .build();

        var header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keys.activeKeyId())
                .build();

        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    @Override
    public Duration accessTokenTtl() {
        return props.accessTtl();
    }
}
```

- [ ] **Step 7: Verificar que pasan**

Run: `./gradlew test --tests '*RsaTokenIssuerTest*'`
Esperado: PASA, 7 tests.

Si `JwsHeader.with(...).keyId(...)` no compila, comprueba el nombre exacto del
método en la versión de Spring Security que resolvió Gradle: es `keyId`, pero
verifícalo con `./gradlew dependencies` antes de cambiar nada.

- [ ] **Step 8: Commit**

```bash
git add build.gradle src/main/java src/test/java
git commit -m "$(cat <<'EOF'
feat: emisión de tokens RS256 con JWKS multiclave

Firma asimétrica en lugar del HMAC compartido anterior: un consumidor
puede validar sin poder falsificar. Con un secreto simétrico, cualquier
servicio comprometido podía emitir tokens de admin.

El JWKS admite varias claves a la vez para que rotar no invalide ningún
token vivo. Un test comprueba que la parte privada nunca sale por ahí.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Refresh tokens opacos, rotativos y revocables

Aquí se cierra la escalada de privilegios de §1.1 del spec.

**Files:**
- Create: `application/port/RefreshTokenStore.java`
- Create: `adapter/token/RefreshTokenEntity.java`, `JpaRefreshTokenRepository.java`, `RefreshTokenStoreJpa.java`
- Test: `src/integrationTest/java/com/mobileamericas/authorization/adapter/token/RefreshTokenStoreIT.java` (+ subclases por motor)

**Interfaces:**
- Consumes: `AppRepository`, `UserRepository` (tarea 4).
- Produces: `RefreshTokenStore` con
  - `record IssuedRefreshToken(String value, UUID familyId, Instant expiresAt)`
  - `record RefreshSubject(UUID userId, UUID appId, UUID familyId)`
  - `IssuedRefreshToken issue(UUID userId, UUID appId)`
  - `IssuedRefreshToken rotate(UUID familyId)`
  - `Optional<RefreshSubject> consume(String rawToken)` — marca usado; si ya lo estaba, revoca la familia y devuelve vacío.
  - `void revokeFamily(UUID familyId)`

- [ ] **Step 1: Escribir el test que falla**

`src/integrationTest/java/com/mobileamericas/authorization/adapter/token/RefreshTokenStoreIT.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.BaseIT;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import com.mobileamericas.authorization.application.port.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class RefreshTokenStoreIT extends BaseIT {

    @Autowired RefreshTokenStore store;
    @Autowired AppRepository apps;
    @Autowired UserRepository usuarios;

    private UUID appId() {
        return apps.findByName("admin").orElseThrow().id();
    }

    private UUID userId() {
        return usuarios.findByEmail("usuario1@pendiente.local").orElseThrow().id();
    }

    @Test
    void el_valor_emitido_no_se_guarda_en_claro() {
        var emitido = store.issue(userId(), appId());

        var enBd = jdbc.sql("SELECT count(*) FROM auth_refresh_token WHERE token_hash = :v")
                .param("v", emitido.value()).query(Long.class).single();

        assertThat(enBd).as("el valor en claro no debe estar en la tabla").isZero();
        assertThat(emitido.value()).hasSizeGreaterThan(40);
    }

    @Test
    void un_token_recien_emitido_se_consume_una_vez() {
        var emitido = store.issue(userId(), appId());

        var sujeto = store.consume(emitido.value());

        assertThat(sujeto).isPresent();
        assertThat(sujeto.get().userId()).isEqualTo(userId());
        assertThat(sujeto.get().appId()).isEqualTo(appId());
        assertThat(sujeto.get().familyId()).isEqualTo(emitido.familyId());
    }

    @Test
    void reutilizar_un_token_ya_consumido_revoca_la_familia_entera() {
        var primero = store.issue(userId(), appId());
        store.consume(primero.value());
        var segundo = store.rotate(primero.familyId());

        // Alguien obtuvo una copia del primero y lo reutiliza.
        var reutilizacion = store.consume(primero.value());

        assertThat(reutilizacion).as("un token ya usado no vale").isEmpty();
        assertThat(store.consume(segundo.value()))
                .as("la familia entera queda revocada, incluido el token legítimo")
                .isEmpty();
    }

    @Test
    void un_token_inventado_no_se_consume() {
        assertThat(store.consume("token-que-nadie-emitio")).isEmpty();
    }

    @Test
    void revocar_la_familia_invalida_el_token_vivo() {
        var emitido = store.issue(userId(), appId());

        store.revokeFamily(emitido.familyId());

        assertThat(store.consume(emitido.value())).isEmpty();
    }

    @Test
    void la_rotacion_mantiene_la_familia_y_cambia_el_valor() {
        var primero = store.issue(userId(), appId());
        store.consume(primero.value());

        var segundo = store.rotate(primero.familyId());

        assertThat(segundo.familyId()).isEqualTo(primero.familyId());
        assertThat(segundo.value()).isNotEqualTo(primero.value());
    }
}
```

Más las dos subclases por motor, idénticas en forma a las de la tarea 4
(`RefreshTokenStoreMySqlIT` con `MySQLContainer<>("mysql:8.4")` y
`concatenador()` devolviendo `"), ':', ("`; `RefreshTokenStorePostgresIT` con
`PostgreSQLContainer<>("postgres:17")` y `concatenador()` devolviendo `"||"`).

- [ ] **Step 2: Verificar que falla**

Run: `./gradlew integrationTest --tests '*RefreshTokenStore*'`
Esperado: FALLA al compilar — `RefreshTokenStore` no existe.

- [ ] **Step 3: Escribir el puerto**

`application/port/RefreshTokenStore.java`:

```java
package com.mobileamericas.authorization.application.port;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh tokens opacos, rotativos y revocables.
 *
 * Opacos y no JWT a propósito: un JWT no se puede revocar antes de que expire
 * sin una lista de rechazados, que es exactamente la tabla que esto ya es.
 */
public interface RefreshTokenStore {

    record IssuedRefreshToken(String value, UUID familyId, Instant expiresAt) {}

    record RefreshSubject(UUID userId, UUID appId, UUID familyId) {}

    IssuedRefreshToken issue(UUID userId, UUID appId);

    IssuedRefreshToken rotate(UUID familyId);

    /**
     * Marca el token como usado y devuelve su sujeto.
     *
     * Si el token ya estaba usado, revoca TODA la familia y devuelve vacío: que
     * un token rotado vuelva a aparecer significa que alguien tiene una copia.
     */
    Optional<RefreshSubject> consume(String rawToken);

    void revokeFamily(UUID familyId);
}
```

- [ ] **Step 4: Escribir la entidad y el repositorio JPA**

`adapter/token/RefreshTokenEntity.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_refresh_token")
class RefreshTokenEntity {

    @Id
    @Column(length = 36)
    String id;

    @Column(name = "user_id", nullable = false, length = 36)
    String userId;

    @Column(name = "app_id", nullable = false, length = 36)
    String appId;

    /** SHA-256 en hexadecimal. Nunca el valor en claro. */
    @Column(name = "token_hash", nullable = false, length = 64)
    String tokenHash;

    @Column(name = "family_id", nullable = false, length = 36)
    String familyId;

    @Column(name = "expires_at", nullable = false)
    Instant expiresAt;

    @Column(name = "used_at")
    Instant usedAt;

    @Column(name = "revoked_at")
    Instant revokedAt;

    @Column(name = "created_at", nullable = false)
    Instant createdAt;

    protected RefreshTokenEntity() {}
}
```

`adapter/token/JpaRefreshTokenRepository.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

interface JpaRefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Query("""
            UPDATE RefreshTokenEntity t SET t.revokedAt = :ahora
             WHERE t.familyId = :familyId AND t.revokedAt IS NULL
            """)
    void revokeFamily(@Param("familyId") String familyId, @Param("ahora") Instant ahora);
}
```

- [ ] **Step 5: Escribir la implementación**

`adapter/token/RefreshTokenStoreJpa.java`:

```java
package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Component
class RefreshTokenStoreJpa implements RefreshTokenStore {

    private static final SecureRandom ALEATORIO = new SecureRandom();

    private final JpaRefreshTokenRepository jpa;
    private final JwtProperties props;

    RefreshTokenStoreJpa(JpaRefreshTokenRepository jpa, JwtProperties props) {
        this.jpa = jpa;
        this.props = props;
    }

    @Override
    @Transactional
    public IssuedRefreshToken issue(UUID userId, UUID appId) {
        return crear(userId, appId, UUID.randomUUID());
    }

    @Override
    @Transactional
    public IssuedRefreshToken rotate(UUID familyId) {
        // El sujeto se toma de la familia, no de ningún token que llegue de fuera.
        var anterior = jpa.findAll().stream()
                .filter(t -> t.familyId.equals(familyId.toString()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Familia desconocida: " + familyId));

        return crear(UUID.fromString(anterior.userId), UUID.fromString(anterior.appId), familyId);
    }

    private IssuedRefreshToken crear(UUID userId, UUID appId, UUID familyId) {
        var bytes = new byte[32];              // 256 bits
        ALEATORIO.nextBytes(bytes);
        var valor = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        var expira = Instant.now().plus(props.refreshTtl());

        var e = new RefreshTokenEntity();
        e.id = UUID.randomUUID().toString();
        e.userId = userId.toString();
        e.appId = appId.toString();
        e.tokenHash = sha256(valor);
        e.familyId = familyId.toString();
        e.expiresAt = expira;
        e.createdAt = Instant.now();
        jpa.save(e);

        return new IssuedRefreshToken(valor, familyId, expira);
    }

    @Override
    @Transactional
    public Optional<RefreshSubject> consume(String rawToken) {
        var encontrado = jpa.findByTokenHash(sha256(rawToken));
        if (encontrado.isEmpty()) {
            return Optional.empty();
        }
        var t = encontrado.get();
        var ahora = Instant.now();

        // Reutilización: el token ya se usó. Alguien tiene una copia, así que
        // cae la familia entera, incluido el token legítimo en circulación.
        if (t.usedAt != null) {
            jpa.revokeFamily(t.familyId, ahora);
            return Optional.empty();
        }
        if (t.revokedAt != null || t.expiresAt.isBefore(ahora)) {
            return Optional.empty();
        }

        t.usedAt = ahora;
        jpa.save(t);

        return Optional.of(new RefreshSubject(
                UUID.fromString(t.userId), UUID.fromString(t.appId), UUID.fromString(t.familyId)));
    }

    @Override
    @Transactional
    public void revokeFamily(UUID familyId) {
        jpa.revokeFamily(familyId.toString(), Instant.now());
    }

    private static String sha256(String valor) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(valor.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no disponible en esta JVM.", e);
        }
    }
}
```

> Nota: `rotate()` usa `findAll()` filtrando en memoria, que es correcto pero
> ineficiente. Al implementar, sustitúyelo por un método derivado
> `Optional<RefreshTokenEntity> findFirstByFamilyIdOrderByCreatedAtDesc(String familyId)`
> en `JpaRefreshTokenRepository` y úsalo aquí. El test no cambia.

- [ ] **Step 6: Verificar que pasan en los dos motores**

Run: `./gradlew integrationTest --tests '*RefreshTokenStore*'`
Esperado: PASA, 12 tests (6 × 2 motores).

- [ ] **Step 7: Commit**

```bash
git add src/main/java src/integrationTest
git commit -m "$(cat <<'EOF'
feat: refresh tokens opacos, rotativos y revocables

Se guarda el SHA-256 del token, nunca el valor: un volcado de la tabla no
permite suplantar a nadie. Un test lo comprueba.

La rotación toma el sujeto de la familia y no de ningún token entrante,
que es lo que cierra la escalada de privilegios de JwtUtil: allí los
claims se copiaban de un access token decodificado sin verificar firma.

Reutilizar un token ya rotado revoca la familia entera: que reaparezca
significa que alguien tiene una copia.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Verificación de la identidad de Google

**Files:**
- Create: `application/port/IdentityVerifier.java`
- Create: `adapter/google/GoogleIdentityVerifier.java`
- Create: `adapter/google/GoogleProperties.java`
- Test: `src/test/java/com/mobileamericas/authorization/adapter/google/GoogleIdentityVerifierTest.java`

**Interfaces:**
- Consumes: `AppRepository` (tarea 4).
- Produces: `IdentityVerifier` con
  - `record VerifiedIdentity(String email, String fullName, App app)`
  - `VerifiedIdentity verify(String idToken)` — lanza `IdentityRejectedException` si el token no vale o su `aud` no corresponde a ninguna app.

- [ ] **Step 1: Escribir el test que falla**

`src/test/java/com/mobileamericas/authorization/adapter/google/GoogleIdentityVerifierTest.java`:

```java
package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.domain.App;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.nimbusds.jose.jwk.source.ImmutableJWKSet.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GoogleIdentityVerifierTest {

    private static final App ADMIN =
            new App(UUID.randomUUID(), "admin", "cliente-admin", null, true);

    private RSAKey clave;
    private GoogleIdentityVerifier verificador;

    /** Repositorio de apps mínimo, en memoria: esta capa no necesita base de datos. */
    private static AppRepository apps() {
        return new AppRepository() {
            @Override public Optional<App> findByGoogleClientId(String id) {
                return "cliente-admin".equals(id) ? Optional.of(ADMIN) : Optional.empty();
            }
            @Override public Optional<App> findByName(String n) {
                return "admin".equals(n) ? Optional.of(ADMIN) : Optional.empty();
            }
            @Override public Optional<App> findById(UUID id) {
                return ADMIN.id().equals(id) ? Optional.of(ADMIN) : Optional.empty();
            }
            @Override public Set<String> resourceCatalogue(UUID appId) { return Set.of("usuarios"); }
        };
    }

    @BeforeEach
    void preparar() throws Exception {
        clave = new RSAKeyGenerator(2048).keyID("google-falso").generate();
        // Se inyecta un decodificador con la clave del test: la suite no habla
        // con Google. En producción el decodificador apunta al JWKS de Google.
        var decodificador = NimbusJwtDecoder.withPublicKey(clave.toRSAPublicKey()).build();
        verificador = new GoogleIdentityVerifier(decodificador, apps());
    }

    private String tokenDeGoogleCon(String aud, String email, Instant expira) {
        var encoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
                new com.nimbusds.jose.jwk.JWKSet(clave)));
        var claims = JwtClaimsSet.builder()
                .issuer("https://accounts.google.com")
                .subject("1234567890")
                .audience(List.of(aud))
                .issuedAt(Instant.now())
                .expiresAt(expira)
                .claim("email", email)
                .claim("name", "Persona de Prueba")
                .build();
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId("google-falso").build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    @Test
    void resuelve_la_app_a_partir_del_audience() {
        var token = tokenDeGoogleCon("cliente-admin", "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        var identidad = verificador.verify(token);

        assertThat(identidad.email()).isEqualTo("persona@ejemplo.com");
        assertThat(identidad.fullName()).isEqualTo("Persona de Prueba");
        assertThat(identidad.app().name()).isEqualTo("admin");
    }

    @Test
    void rechaza_un_audience_que_no_corresponde_a_ninguna_app() {
        var token = tokenDeGoogleCon("cliente-desconocido", "persona@ejemplo.com",
                Instant.now().plus(1, ChronoUnit.HOURS));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("aplicación");
    }

    @Test
    void rechaza_un_token_caducado() {
        var token = tokenDeGoogleCon("cliente-admin", "persona@ejemplo.com",
                Instant.now().minus(1, ChronoUnit.MINUTES));

        assertThatThrownBy(() -> verificador.verify(token))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class);
    }

    @Test
    void rechaza_un_token_con_firma_ajena() throws Exception {
        var otraClave = new RSAKeyGenerator(2048).keyID("google-falso").generate();
        var encoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
                new com.nimbusds.jose.jwk.JWKSet(otraClave)));
        var claims = JwtClaimsSet.builder()
                .issuer("https://accounts.google.com").subject("1")
                .audience(List.of("cliente-admin"))
                .issuedAt(Instant.now()).expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                .claim("email", "intruso@ejemplo.com").build();
        var falso = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId("google-falso").build(), claims))
                .getTokenValue();

        assertThatThrownBy(() -> verificador.verify(falso))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class);
    }

    @Test
    void rechaza_un_token_sin_email() {
        var encoder = new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
                new com.nimbusds.jose.jwk.JWKSet(clave)));
        var claims = JwtClaimsSet.builder()
                .issuer("https://accounts.google.com").subject("1")
                .audience(List.of("cliente-admin"))
                .issuedAt(Instant.now()).expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
        var sinEmail = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId("google-falso").build(), claims))
                .getTokenValue();

        assertThatThrownBy(() -> verificador.verify(sinEmail))
                .isInstanceOf(IdentityVerifier.IdentityRejectedException.class)
                .hasMessageContaining("email");
    }
}
```

> Al implementar, limpia el `import static` de `ImmutableJWKSet` que quedó sin
> usar y extrae el emisor de tokens falsos a un método auxiliar del test.

- [ ] **Step 2: Verificar que falla**

Run: `./gradlew test --tests '*GoogleIdentityVerifierTest*'`
Esperado: FALLA al compilar.

- [ ] **Step 3: Escribir el puerto**

`application/port/IdentityVerifier.java`:

```java
package com.mobileamericas.authorization.application.port;

import com.mobileamericas.authorization.domain.App;

public interface IdentityVerifier {

    record VerifiedIdentity(String email, String fullName, App app) {}

    /** @throws IdentityRejectedException si el token no vale o su 'aud' no es de ninguna app. */
    VerifiedIdentity verify(String idToken);

    class IdentityRejectedException extends RuntimeException {
        public IdentityRejectedException(String mensaje) {
            super(mensaje);
        }
        public IdentityRejectedException(String mensaje, Throwable causa) {
            super(mensaje, causa);
        }
    }
}
```

- [ ] **Step 4: Escribir la configuración y el verificador**

`adapter/google/GoogleProperties.java`:

```java
package com.mobileamericas.authorization.adapter.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authorization.google")
public record GoogleProperties(String jwkSetUri, String issuer) {

    public GoogleProperties {
        jwkSetUri = jwkSetUri == null ? "https://www.googleapis.com/oauth2/v3/certs" : jwkSetUri;
        issuer = issuer == null ? "https://accounts.google.com" : issuer;
    }
}
```

`adapter/google/GoogleIdentityVerifier.java`:

```java
package com.mobileamericas.authorization.adapter.google;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

/**
 * Verifica el ID token de Google y resuelve a qué app pertenece.
 *
 * El JwtDecoder es un singleton con caché de claves. El código anterior creaba
 * un GoogleIdTokenVerifier y un NetHttpTransport nuevos en CADA petición, lo que
 * anulaba la caché y añadía una ida y vuelta a Google por llamada.
 *
 * La app se deduce del 'aud' del token, es decir, del client ID de OAuth con el
 * que el usuario entró. Ese mapeo vive en auth_app.google_client_id.
 */
@Component
public class GoogleIdentityVerifier implements IdentityVerifier {

    private final JwtDecoder decoder;
    private final AppRepository apps;

    public GoogleIdentityVerifier(JwtDecoder googleJwtDecoder, AppRepository apps) {
        this.decoder = googleJwtDecoder;
        this.apps = apps;
    }

    @Override
    public VerifiedIdentity verify(String idToken) {
        Jwt jwt;
        try {
            jwt = decoder.decode(idToken);
        } catch (JwtException e) {
            throw new IdentityRejectedException("El token de Google no es válido.", e);
        }

        var audiencias = jwt.getAudience();
        if (audiencias == null || audiencias.isEmpty()) {
            throw new IdentityRejectedException("El token de Google no declara audiencia.");
        }

        var app = audiencias.stream()
                .map(apps::findByGoogleClientId)
                .flatMap(java.util.Optional::stream)
                .findFirst()
                .orElseThrow(() -> new IdentityRejectedException(
                        "El token no corresponde a ninguna aplicación registrada."));

        if (!app.active()) {
            throw new IdentityRejectedException(
                    "La aplicación '%s' está desactivada.".formatted(app.name()));
        }

        var email = jwt.getClaimAsString("email");
        if (email == null || email.isBlank()) {
            throw new IdentityRejectedException("El token de Google no trae email.");
        }

        return new VerifiedIdentity(email, jwt.getClaimAsString("name"), app);
    }
}
```

- [ ] **Step 5: Verificar que pasan**

Run: `./gradlew test --tests '*GoogleIdentityVerifierTest*'`
Esperado: PASA, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add src/main/java src/test/java
git commit -m "$(cat <<'EOF'
feat: verificación del ID token de Google con decodificador singleton

El JwtDecoder se crea una vez y cachea las claves de Google. El código
anterior construía un GoogleIdTokenVerifier y un NetHttpTransport nuevos
en cada petición, lo que anulaba la caché y añadía una ida y vuelta a
Google por llamada.

La app se resuelve desde auth_app.google_client_id, no desde el YAML, así
que registrar una aplicación deja de requerir un despliegue.

La suite no habla con Google: los tests firman con claves propias.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: El caso de uso — y el test de la escalada de privilegios

**Files:**
- Create: `application/service/AuthenticationService.java`
- Create: `application/service/AuthenticationResult.java`
- Test: `src/test/java/com/mobileamericas/authorization/application/service/AuthenticationServiceTest.java`

**Interfaces:**
- Consumes: `IdentityVerifier` (7), `UserRepository`/`AppRepository` (4), `TokenIssuer` (5), `RefreshTokenStore` (6).
- Produces: `AuthenticationService` con
  - `AuthenticationResult authenticate(String googleIdToken)`
  - `AuthenticationResult refresh(String rawRefreshToken)`
  - `void logout(String rawRefreshToken)`
  - `record AuthenticationResult(String accessToken, String refreshToken, Duration accessTtl, Instant refreshExpiresAt)`
  - `class AccessDeniedException extends RuntimeException`

- [ ] **Step 1: Escribir el test que falla**

`src/test/java/com/mobileamericas/authorization/application/service/AuthenticationServiceTest.java`:

```java
package com.mobileamericas.authorization.application.service;

import com.mobileamericas.authorization.application.port.*;
import com.mobileamericas.authorization.domain.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationServiceTest {

    private static final UUID APP_ID = UUID.randomUUID();
    private static final App APP = new App(APP_ID, "trafficflow", "cliente-tf", null, true);
    private static final UUID USER_ID = UUID.randomUUID();

    private final Map<String, String> tokensEmitidos = new LinkedHashMap<>();
    private User usuarioEnBd;
    private AuthenticationService servicio;

    private static User usuarioCon(Set<Permission> permisos) {
        var rol = new Role(UUID.randomUUID(), "operador", APP_ID, permisos);
        return new User(USER_ID, "persona@ejemplo.com", "Persona", true, Set.of(rol));
    }

    @BeforeEach
    void preparar() {
        usuarioEnBd = usuarioCon(Set.of(Permission.parse("campanas:leer")));
        servicio = new AuthenticationService(
                idToken -> new IdentityVerifier.VerifiedIdentity("persona@ejemplo.com", "Persona", APP),
                new UserRepository() {
                    @Override public Optional<User> findByEmail(String e) { return Optional.of(usuarioEnBd); }
                    @Override public Optional<User> findById(UUID id) { return Optional.of(usuarioEnBd); }
                },
                new AppRepository() {
                    @Override public Optional<App> findByGoogleClientId(String id) { return Optional.of(APP); }
                    @Override public Optional<App> findByName(String n) { return Optional.of(APP); }
                    @Override public Optional<App> findById(UUID id) { return Optional.of(APP); }
                    @Override public Set<String> resourceCatalogue(UUID id) { return Set.of("campanas"); }
                },
                new TokenIssuer() {
                    @Override public String issueAccessToken(AccessGrant g) {
                        var token = "access-" + tokensEmitidos.size();
                        tokensEmitidos.put(token, String.join(",", new TreeSet<>(g.authorities())));
                        return token;
                    }
                    @Override public Duration accessTokenTtl() { return Duration.ofMinutes(15); }
                },
                new RefreshTokenStoreFalso());
    }

    /** Almacén en memoria con la misma semántica que el real. */
    private static final class RefreshTokenStoreFalso implements RefreshTokenStore {
        private final Map<String, RefreshSubject> vivos = new LinkedHashMap<>();
        private final Set<UUID> revocadas = new HashSet<>();
        private int n;

        @Override public IssuedRefreshToken issue(UUID userId, UUID appId) {
            return crear(userId, appId, UUID.randomUUID());
        }
        @Override public IssuedRefreshToken rotate(UUID familyId) {
            var previo = vivos.values().stream()
                    .filter(s -> s.familyId().equals(familyId)).findFirst().orElseThrow();
            return crear(previo.userId(), previo.appId(), familyId);
        }
        private IssuedRefreshToken crear(UUID userId, UUID appId, UUID familyId) {
            var valor = "refresh-" + (n++);
            vivos.put(valor, new RefreshSubject(userId, appId, familyId));
            return new IssuedRefreshToken(valor, familyId, Instant.now().plus(Duration.ofHours(12)));
        }
        @Override public Optional<RefreshSubject> consume(String raw) {
            var s = vivos.remove(raw);
            if (s == null || revocadas.contains(s.familyId())) return Optional.empty();
            return Optional.of(s);
        }
        @Override public void revokeFamily(UUID familyId) {
            revocadas.add(familyId);
        }
    }

    @Test
    void autentica_y_emite_los_dos_tokens() {
        var resultado = servicio.authenticate("token-de-google");

        assertThat(resultado.accessToken()).isEqualTo("access-0");
        assertThat(resultado.refreshToken()).isEqualTo("refresh-0");
        assertThat(tokensEmitidos.get("access-0")).isEqualTo("campanas:leer");
    }

    @Test
    void rechaza_a_quien_no_tiene_ningun_rol_en_la_app() {
        usuarioEnBd = new User(USER_ID, "persona@ejemplo.com", "Persona", true, Set.of());

        assertThatThrownBy(() -> servicio.authenticate("token-de-google"))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }

    @Test
    void al_renovar_los_permisos_se_releen_de_la_base_de_datos() {
        // ESTE ES EL TEST DE LA ESCALADA DE PRIVILEGIOS.
        //
        // En develop, refresh() hacía JWT.decode(accessToken) -sin verificar
        // firma- y copiaba sus claims al token nuevo. Bastaba fabricar un access
        // token con roles:[admin] y presentarlo con cualquier refresh válido.
        //
        // Aquí refresh() no recibe el access token siquiera, y los permisos
        // salen del repositorio. Si alguien degrada al usuario en la base de
        // datos, la renovación lo refleja.
        var primero = servicio.authenticate("token-de-google");
        assertThat(tokensEmitidos.get(primero.accessToken())).isEqualTo("campanas:leer");

        usuarioEnBd = usuarioCon(Set.of());   // le quitan el permiso

        var renovado = servicio.refresh(primero.refreshToken());

        assertThat(tokensEmitidos.get(renovado.accessToken()))
                .as("los permisos se releen de la BD, no se copian del token anterior")
                .isEmpty();
    }

    @Test
    void al_renovar_un_ascenso_tambien_se_refleja() {
        var primero = servicio.authenticate("token-de-google");

        usuarioEnBd = usuarioCon(Set.of(Permission.parse("*:*")));

        var renovado = servicio.refresh(primero.refreshToken());

        assertThat(tokensEmitidos.get(renovado.accessToken()))
                .isEqualTo("campanas:borrar,campanas:crear,campanas:editar,campanas:leer");
    }

    @Test
    void un_refresh_token_desconocido_se_rechaza() {
        assertThatThrownBy(() -> servicio.refresh("no-emitido"))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }

    @Test
    void el_logout_revoca_la_familia() {
        var sesion = servicio.authenticate("token-de-google");

        servicio.logout(sesion.refreshToken());

        assertThatThrownBy(() -> servicio.refresh(sesion.refreshToken()))
                .isInstanceOf(AuthenticationService.AccessDeniedException.class);
    }
}
```

- [ ] **Step 2: Verificar que falla**

Run: `./gradlew test --tests '*AuthenticationServiceTest*'`
Esperado: FALLA al compilar.

- [ ] **Step 3: Escribir el resultado**

`application/service/AuthenticationResult.java`:

```java
package com.mobileamericas.authorization.application.service;

import java.time.Duration;
import java.time.Instant;

public record AuthenticationResult(
        String accessToken,
        String refreshToken,
        Duration accessTtl,
        Instant refreshExpiresAt) {}
```

- [ ] **Step 4: Escribir el servicio**

`application/service/AuthenticationService.java`:

```java
package com.mobileamericas.authorization.application.service;

import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import com.mobileamericas.authorization.domain.App;
import com.mobileamericas.authorization.domain.User;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthenticationService {

    private final IdentityVerifier identidades;
    private final UserRepository usuarios;
    private final AppRepository apps;
    private final TokenIssuer emisor;
    private final RefreshTokenStore refrescos;

    public AuthenticationService(IdentityVerifier identidades, UserRepository usuarios,
                                 AppRepository apps, TokenIssuer emisor,
                                 RefreshTokenStore refrescos) {
        this.identidades = identidades;
        this.usuarios = usuarios;
        this.apps = apps;
        this.emisor = emisor;
        this.refrescos = refrescos;
    }

    public AuthenticationResult authenticate(String googleIdToken) {
        var identidad = identidades.verify(googleIdToken);

        var usuario = usuarios.findByEmail(identidad.email())
                .orElseThrow(() -> new AccessDeniedException(
                        "El usuario no está dado de alta en la plataforma."));

        return emitir(usuario, identidad.app());
    }

    /**
     * Renueva la sesión.
     *
     * No recibe el access token. Los roles y permisos se resuelven consultando
     * el repositorio por el userId que guarda la familia del refresh, así que un
     * access token fabricado no aporta nada. Es lo que cierra la escalada de
     * privilegios que tenía JwtUtil.refreshAccessToken().
     */
    public AuthenticationResult refresh(String rawRefreshToken) {
        var sujeto = refrescos.consume(rawRefreshToken)
                .orElseThrow(() -> new AccessDeniedException(
                        "El refresh token no es válido o ya se usó."));

        var usuario = usuarios.findById(sujeto.userId())
                .orElseThrow(() -> new AccessDeniedException("El usuario ya no existe."));

        var app = apps.findById(sujeto.appId())
                .orElseThrow(() -> new AccessDeniedException("La aplicación ya no existe."));

        var grant = grantDe(usuario, app);
        var rotado = refrescos.rotate(sujeto.familyId());

        return new AuthenticationResult(
                emisor.issueAccessToken(grant), rotado.value(),
                emisor.accessTokenTtl(), rotado.expiresAt());
    }

    public void logout(String rawRefreshToken) {
        refrescos.consume(rawRefreshToken)
                .ifPresent(sujeto -> refrescos.revokeFamily(sujeto.familyId()));
    }

    private AuthenticationResult emitir(User usuario, App app) {
        var grant = grantDe(usuario, app);
        var refresh = refrescos.issue(usuario.id(), app.id());

        return new AuthenticationResult(
                emisor.issueAccessToken(grant), refresh.value(),
                emisor.accessTokenTtl(), refresh.expiresAt());
    }

    private AccessGrant grantDe(User usuario, App app) {
        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));
        if (grant.isEmpty()) {
            throw new AccessDeniedException(
                    "El usuario no tiene roles ni permisos en '%s'.".formatted(app.name()));
        }
        return grant;
    }

    public static class AccessDeniedException extends RuntimeException {
        public AccessDeniedException(String mensaje) {
            super(mensaje);
        }
    }
}
```

- [ ] **Step 5: Verificar que pasan**

Run: `./gradlew test --tests '*AuthenticationServiceTest*'`
Esperado: PASA, 6 tests.

- [ ] **Step 6: Verificar que la capa de aplicación no toca el framework de web**

Run:
```bash
grep -rn "jakarta.servlet\|org.springframework.web" src/main/java/com/mobileamericas/authorization/application/ \
  && echo "VIOLACIÓN" || echo "limpio"
```
Esperado: `limpio`.

- [ ] **Step 7: Commit**

```bash
git add src/main/java src/test/java
git commit -m "$(cat <<'EOF'
feat: caso de uso de autenticación con renovación segura

refresh() no recibe el access token: los roles y permisos se resuelven
consultando el repositorio por el userId de la familia del refresh. Un
access token fabricado no aporta nada.

Hay un test que reproduce la escalada de privilegios de develop y exige
que la renovación refleje lo que dice la base de datos, tanto si al
usuario le quitan permisos como si se los dan.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Capa web, seguridad y cookies

**Files:**
- Create: `web/AuthController.java`, `web/JwksController.java`, `web/MeController.java`
- Create: `web/ApiExceptionHandler.java`
- Create: `web/CookieFactory.java`
- Create: `web/security/SecurityConfig.java`
- Create: `config/BeansConfig.java`
- Test: `src/test/java/com/mobileamericas/authorization/web/AuthControllerTest.java`
- Test: `src/integrationTest/java/com/mobileamericas/authorization/web/SeguridadIT.java` (+ subclases)

**Interfaces:**
- Consumes: `AuthenticationService` (8), `JwtKeys` (5).
- Produces: los endpoints de §6 del spec.

- [ ] **Step 1: Escribir los tests que fallan**

`src/test/java/com/mobileamericas/authorization/web/AuthControllerTest.java`:

```java
package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.service.AuthenticationResult;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired MockMvc mvc;
    @MockBean AuthenticationService servicio;

    @Test
    void el_login_devuelve_las_cookies_y_nada_en_el_cuerpo() throws Exception {
        given(servicio.authenticate(anyString())).willReturn(new AuthenticationResult(
                "el-access-token", "el-refresh-token",
                Duration.ofMinutes(15), Instant.now().plus(Duration.ofHours(12))));

        mvc.perform(post("/v1/auth/google")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("token-de-google"))
                .andExpect(status().isNoContent())
                // El token NO va en el cuerpo: antes iba, y la UI lo guardaba en
                // localStorage, que es legible por cualquier XSS.
                .andExpect(content().string(""))
                .andExpect(cookie().exists("ma_access"))
                .andExpect(cookie().httpOnly("ma_access", true))
                .andExpect(cookie().secure("ma_access", true))
                .andExpect(cookie().exists("ma_refresh"))
                .andExpect(cookie().httpOnly("ma_refresh", true));
    }

    @Test
    void un_acceso_denegado_responde_403_en_problem_json() throws Exception {
        willThrow(new AuthenticationService.AccessDeniedException("Sin roles en la aplicación."))
                .given(servicio).authenticate(anyString());

        mvc.perform(post("/v1/auth/google")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("token-de-google"))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.detail").value("Sin roles en la aplicación."))
                // Nunca una traza: el ResponseDto anterior devolvía
                // e.getStackTrace()[0] al cliente.
                .andExpect(jsonPath("$.stackTrace").doesNotExist());
    }

    @Test
    void el_logout_borra_las_cookies() throws Exception {
        mvc.perform(post("/v1/auth/logout").cookie(
                        new jakarta.servlet.http.Cookie("ma_refresh", "el-refresh-token")))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("ma_access", 0))
                .andExpect(cookie().maxAge("ma_refresh", 0));
    }
}
```

`src/integrationTest/java/com/mobileamericas/authorization/web/SeguridadIT.java`:

```java
package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.BaseIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class SeguridadIT extends BaseIT {

    @Autowired TestRestTemplate http;

    @Test
    void el_endpoint_env_ya_no_existe() {
        // Era público y volcaba System.getenv(), que incluye la contraseña de la
        // base de datos y el secreto de firma.
        var r = http.getForEntity("/v1/authorization/env", String.class);

        assertThat(r.getStatusCode()).isIn(HttpStatus.NOT_FOUND, HttpStatus.UNAUTHORIZED);
        assertThat(r.getBody() == null ? "" : r.getBody())
                .doesNotContain("DB_MA_PLATFORM_PASSWORD")
                .doesNotContain("JWT_PRIVATE_KEY");
    }

    @Test
    void una_ruta_no_declarada_exige_autenticacion() {
        // Antes: .anyRequest().permitAll()
        assertThat(http.getForEntity("/v1/lo-que-sea", String.class).getStatusCode())
                .isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.NOT_FOUND);
    }

    @Test
    void el_jwks_es_publico_y_solo_trae_claves_publicas() {
        var r = http.getForEntity("/.well-known/jwks.json", String.class);

        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("\"keys\"").contains("\"n\"").contains("\"e\"");
        assertThat(r.getBody()).doesNotContain("\"d\"").doesNotContain("\"p\"");
    }

    @Test
    void me_sin_token_responde_401() {
        assertThat(http.getForEntity("/v1/auth/me", String.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
```

Más las dos subclases por motor, como en tareas anteriores.

- [ ] **Step 2: Verificar que fallan**

Run: `./gradlew test integrationTest`
Esperado: FALLA — no existen los controladores.

- [ ] **Step 3: Escribir las cookies y los controladores**

`web/CookieFactory.java`:

```java
package com.mobileamericas.authorization.web;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * HttpOnly, Secure y SameSite=Lax, los tres.
 *
 * En develop estaban las tres líneas comentadas y el token viajaba además en el
 * cuerpo de la respuesta, de donde MA-Platform-UI lo copiaba a localStorage.
 * Cualquier XSS podía leerlo.
 */
@Component
class CookieFactory {

    static final String ACCESS = "ma_access";
    static final String REFRESH = "ma_refresh";

    ResponseCookie access(String valor, Duration ttl) {
        return base(ACCESS, valor).maxAge(ttl).build();
    }

    ResponseCookie refresh(String valor, Duration ttl) {
        return base(REFRESH, valor).maxAge(ttl).build();
    }

    ResponseCookie borrar(String nombre) {
        return base(nombre, "").maxAge(Duration.ZERO).build();
    }

    private ResponseCookie.ResponseCookieBuilder base(String nombre, String valor) {
        return ResponseCookie.from(nombre, valor)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/");
    }
}
```

`web/AuthController.java`:

```java
package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.service.AuthenticationResult;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping("/v1/auth")
class AuthController {

    private final AuthenticationService servicio;
    private final CookieFactory cookies;

    AuthController(AuthenticationService servicio, CookieFactory cookies) {
        this.servicio = servicio;
        this.cookies = cookies;
    }

    @PostMapping("/google")
    ResponseEntity<Void> google(@RequestBody String googleIdToken) {
        return conCookies(servicio.authenticate(googleIdToken.trim()));
    }

    @PostMapping("/refresh")
    ResponseEntity<Void> refresh(@CookieValue(CookieFactory.REFRESH) String refreshToken) {
        return conCookies(servicio.refresh(refreshToken));
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(
            @CookieValue(value = CookieFactory.REFRESH, required = false) String refreshToken) {
        if (refreshToken != null) {
            servicio.logout(refreshToken);
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookies.borrar(CookieFactory.ACCESS).toString())
                .header(HttpHeaders.SET_COOKIE, cookies.borrar(CookieFactory.REFRESH).toString())
                .build();
    }

    /** El cuerpo va vacío a propósito: el token no debe ser legible por JavaScript. */
    private ResponseEntity<Void> conCookies(AuthenticationResult r) {
        var ttlRefresh = Duration.between(Instant.now(), r.refreshExpiresAt());
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE,
                        cookies.access(r.accessToken(), r.accessTtl()).toString())
                .header(HttpHeaders.SET_COOKIE,
                        cookies.refresh(r.refreshToken(), ttlRefresh).toString())
                .build();
    }
}
```

`web/JwksController.java`:

```java
package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.adapter.token.JwtKeys;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
class JwksController {

    private final JwtKeys keys;

    JwksController(JwtKeys keys) {
        this.keys = keys;
    }

    /** Lo que consume MS-2 con spring.security.oauth2.resourceserver.jwt.jwk-set-uri. */
    @GetMapping("/.well-known/jwks.json")
    Map<String, Object> jwks() {
        return keys.publicJwks();
    }
}
```

`web/MeController.java`:

```java
package com.mobileamericas.authorization.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
class MeController {

    /** Todo sale del token ya validado: no hace falta tocar la base de datos. */
    @GetMapping("/me")
    Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "id", jwt.getSubject(),
                "email", jwt.getClaimAsString("email"),
                "name", jwt.getClaimAsString("name") == null ? "" : jwt.getClaimAsString("name"),
                "app", jwt.getAudience().getFirst(),
                "roles", jwt.getClaimAsStringList("roles"),
                "permissions", jwt.getClaimAsStringList("permissions"));
    }
}
```

- [ ] **Step 4: Escribir el manejador de errores**

`web/ApiExceptionHandler.java`:

```java
package com.mobileamericas.authorization.web;

import com.mobileamericas.authorization.application.port.IdentityVerifier;
import com.mobileamericas.authorization.application.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Errores en application/problem+json (RFC 7807).
 *
 * El ResponseDto anterior metía e.getStackTrace()[0] en el cuerpo, filtrando
 * rutas de clases y números de línea a quien llamara. Aquí la traza va al log y
 * al cliente solo le llega el motivo.
 */
@RestControllerAdvice
class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(IdentityVerifier.IdentityRejectedException.class)
    ProblemDetail identidadRechazada(IdentityVerifier.IdentityRejectedException e) {
        log.info("Identidad rechazada: {}", e.getMessage());
        var p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, e.getMessage());
        p.setTitle("Identidad no válida");
        return p;
    }

    @ExceptionHandler(AuthenticationService.AccessDeniedException.class)
    ProblemDetail accesoDenegado(AuthenticationService.AccessDeniedException e) {
        log.info("Acceso denegado: {}", e.getMessage());
        var p = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
        p.setTitle("Acceso denegado");
        return p;
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail inesperado(Exception e) {
        log.error("Error no controlado", e);
        var p = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "Error interno.");
        p.setTitle("Error interno");
        return p;
    }
}
```

- [ ] **Step 5: Escribir la configuración de beans y de seguridad**

`config/BeansConfig.java`:

```java
package com.mobileamericas.authorization.config;

import com.mobileamericas.authorization.adapter.google.GoogleProperties;
import com.mobileamericas.authorization.adapter.token.JwtKeys;
import com.mobileamericas.authorization.adapter.token.JwtProperties;
import com.mobileamericas.authorization.adapter.token.RsaTokenIssuer;
import com.mobileamericas.authorization.application.port.TokenIssuer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, GoogleProperties.class})
class BeansConfig {

    /**
     * Las claves de firma se leen de ficheros montados desde un Secret de
     * Kubernetes. La primera de la lista es la activa; las demás siguen en el
     * JWKS para que rotar no invalide ningún token vivo.
     */
    @Bean
    JwtKeys jwtKeys(org.springframework.core.io.ResourceLoader loader,
                    @org.springframework.beans.factory.annotation.Value("${authorization.jwt.key-locations}")
                    List<String> ubicaciones) throws IOException {
        var json = new java.util.ArrayList<String>();
        for (var ubicacion : ubicaciones) {
            Resource r = loader.getResource(ubicacion);
            json.add(new String(r.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        }
        return JwtKeys.fromJson(json);
    }

    @Bean
    TokenIssuer tokenIssuer(JwtKeys keys, JwtProperties props) {
        return new RsaTokenIssuer(keys, props);
    }

    /**
     * Decodificador de los tokens de GOOGLE. Singleton: cachea las claves de
     * Google en lugar de pedirlas en cada petición como hacía el código anterior.
     */
    @Bean
    JwtDecoder googleJwtDecoder(GoogleProperties props) {
        var decoder = NimbusJwtDecoder.withJwkSetUri(props.jwkSetUri()).build();
        decoder.setJwtValidator(
                org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer(
                        props.issuer()));
        return decoder;
    }

    /**
     * Decodificador de NUESTROS tokens, para /v1/auth/me.
     *
     * @Primary porque es el que usa la cadena de seguridad; el de Google se
     * inyecta por nombre en GoogleIdentityVerifier.
     *
     * Usa la clave ACTIVA. Durante una rotación, un token firmado con la clave
     * anterior no valida aquí hasta que su portador renueve, lo que ocurre como
     * mucho 15 minutos después. Los consumidores externos no tienen ese límite:
     * leen el JWKS, que sí publica todas las claves.
     */
    @Bean
    @Primary
    JwtDecoder selfJwtDecoder(JwtKeys keys, JwtProperties props) {
        var decoder = NimbusJwtDecoder.withPublicKey(keys.activePublicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.issuer()));
        return decoder;
    }
}
```

Y en `GoogleIdentityVerifier`, el constructor pasa a tomar el decodificador por
nombre para que no haya ambigüedad:

```java
    public GoogleIdentityVerifier(
            @Qualifier("googleJwtDecoder") JwtDecoder googleJwtDecoder, AppRepository apps) {
```

`web/security/SecurityConfig.java`:

```java
package com.mobileamericas.authorization.web.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
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
    SecurityFilterChain filterChain(HttpSecurity http, CorsConfigurationSource cors)
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
     * Así @PreAuthorize("hasAuthority('campanas:editar')") funciona directamente,
     * en este servicio y en cualquier consumidor.
     */
    private static JwtAuthenticationConverter conversor() {
        var autoridades = new JwtGrantedAuthoritiesConverter();
        autoridades.setAuthorityPrefix("");
        autoridades.setAuthoritiesClaimName("permissions");

        var conversor = new JwtAuthenticationConverter();
        conversor.setJwtGrantedAuthoritiesConverter(autoridades);
        return conversor;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @org.springframework.beans.factory.annotation.Value("${authorization.cors.allowed-origins}")
            List<String> origenes) {
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
```

- [ ] **Step 6: Verificar que pasan**

Run: `./gradlew test integrationTest`
Esperado: PASA. Los `SeguridadIT` necesitan una clave de firma en el perfil de
test; añade a `src/integrationTest/resources/application.yml` una clave RSA JWK
generada para pruebas y la propiedad `authorization.jwt.key-locations`.

- [ ] **Step 7: Commit**

```bash
git add src/main/java src/test/java src/integrationTest
git commit -m "$(cat <<'EOF'
feat: capa web con denegación por defecto y cookies endurecidas

anyRequest().authenticated() en lugar de permitAll(): las cuatro rutas
públicas se enumeran y todo lo demás exige token.

Elimina GET /env, que era público y volcaba System.getenv() incluyendo la
contraseña de la base de datos y el secreto de firma. Hay un test que
comprueba que ya no responde.

Las cookies llevan HttpOnly, Secure y SameSite, y el token deja de viajar
en el cuerpo. Esto rompe MA-Platform-UI, que lo lee desde JavaScript; se
adapta en la fase 3.

Los errores pasan a application/problem+json y la traza va al log, no al
cliente.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Configuración y despliegue

**Files:**
- Create: `src/main/resources/application.yml`, `application-dev.yml`
- Modify: `Dockerfile`
- Modify: `kubernetes/deployment.yaml`
- Modify: `cloudbuild.yaml`
- Create: `README.md`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: imagen desplegable y manifiestos coherentes con los `Service` que ya existen en `MA-Platform-config`.

- [ ] **Step 1: Escribir `application.yml`**

```yaml
server:
  # El Service de MA-Platform-config apunta a 8081 y el ConfigMap define
  # SERVER_PORT: "8081". El fichero anterior fijaba 18080 literal, así que
  # nada podía llegar al pod. Esta línea es el arreglo.
  port: ${SERVER_PORT:8081}
  servlet:
    context-path: /authorization-api
  shutdown: graceful

spring:
  application.name: MA-Platform-Authorization
  threads.virtual.enabled: true      # servicio de pura E/S: Google, JWKS, BD
  datasource:
    url: ${DB_MA_PLATFORM_URL}
    username: ${DB_MA_PLATFORM_USER}
    password: ${DB_MA_PLATFORM_PASSWORD}
    hikari:
      minimum-idle: 5
      maximum-pool-size: 20
      pool-name: AuthHikariCP
  jpa:
    hibernate.ddl-auto: validate     # Flyway manda; Hibernate sólo comprueba
    open-in-view: false
  flyway:
    enabled: true
    locations: classpath:db/migration   # UN solo juego para MySQL y PostgreSQL

management:
  server.port: ${MANAGEMENT_SERVER_PORT:18081}
  endpoint.health:
    probes.enabled: true
    show-details: never              # 'always' filtraba detalles de la BD
  endpoints.web:
    exposure.include: health,info
    base-path: /actuator

authorization:
  jwt:
    issuer: ${JWT_ISSUER:https://auth.mobile-americas.com}
    access-ttl: PT15M
    refresh-ttl: PT12H
    # La primera es la activa. Durante una rotación se declaran dos.
    key-locations: ${JWT_KEY_LOCATIONS:file:/etc/ma-auth/keys/active.jwk}
  google:
    jwk-set-uri: https://www.googleapis.com/oauth2/v3/certs
    issuer: https://accounts.google.com
  cors:
    allowed-origins: ${CORS_ALLOWED_ORIGINS:https://*.mobile-americas.com}

logging.level.com.mobileamericas: INFO
```

`application-dev.yml`:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/ma_platform_auth
    username: ma-platform-user
    password: ma-platform-password

authorization:
  jwt:
    key-locations: classpath:dev-keys/active.jwk
  cors:
    allowed-origins: http://localhost:3000,http://localhost:5173
```

> La clave de `dev-keys/active.jwk` se genera con `RSAKeyGenerator` y se
> commitea **sólo** porque es de desarrollo. Añade un comentario en el fichero
> diciéndolo y comprueba que `JWT_KEY_LOCATIONS` la sobrescribe en los demás
> perfiles.

- [ ] **Step 2: Reescribir el `Dockerfile`**

```dockerfile
FROM eclipse-temurin:25-jre-alpine

ARG PROJECT_NAME=ma-authorization
ENV APP_HOME=/usr/app

WORKDIR $APP_HOME
COPY ./build/libs/${PROJECT_NAME}*.jar ./ma-authorization.jar

# Sin root: la imagen anterior ejecutaba como root con un JDK completo.
RUN addgroup -S app && adduser -S -G app app && chown -R app:app $APP_HOME
USER app

EXPOSE 8081 18081

# Forma exec, sin envoltorio de bash. El Dockerfile anterior generaba un script
# entrypoint.sh, así que SIGTERM llegaba a bash y no a la JVM: el
# terminationGracePeriodSeconds del deployment no servía de nada.
ENTRYPOINT ["java", "-jar", "/usr/app/ma-authorization.jar"]
```

- [ ] **Step 3: Actualizar `kubernetes/deployment.yaml`**

En el `ConfigMap`, quitar nada y dejarlo como está (`SERVER_PORT: "8081"`,
`MANAGEMENT_SERVER_PORT: "18081"` ya son correctos). En el contenedor:

```yaml
          ports:
            - { name: http,       containerPort: 8081 }
            - { name: management, containerPort: 18081 }
          livenessProbe:
            httpGet: { path: /actuator/health/liveness, port: management }
            initialDelaySeconds: 20
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /actuator/health/readiness, port: management }
            initialDelaySeconds: 10
            periodSeconds: 5
          env:
            - name: JAVA_TOOL_OPTIONS
              value: "-XX:MaxRAMPercentage=50 -XX:InitialRAMPercentage=25"
            - name: JWT_KEY_LOCATIONS
              value: "file:/etc/ma-auth/keys/active.jwk"
          volumeMounts:
            - { name: jwt-keys, mountPath: /etc/ma-auth/keys, readOnly: true }
      volumes:
        - name: jwt-keys
          secret:
            secretName: ma-auth-jwt-keys
```

Y **eliminar** del bloque `env` las entradas `ADMIN_CLIENT_ID` y `FGF_CLIENT_ID`:
el mapeo cliente→app vive ahora en `auth_app.google_client_id`.

- [ ] **Step 4: Actualizar `cloudbuild.yaml`**

```diff
 substitutions:
-  _IMAGE_NAME: gcr.io/sms-ma-shaplatform/ma-authorization
+  _IMAGE_NAME: us-east1-docker.pkg.dev/sms-ma-platform/ma-platform/ma-authorization
```

Y borrar el paso `Replace using envsubst` completo, junto con las sustituciones
`_ADMIN_CLIENT_ID` y `_FGF_CLIENT_ID`: ya no hay nada que sustituir.

Añadir un paso de pruebas antes de construir la imagen:

```yaml
  - name: 'gradle:jdk25'
    entrypoint: 'gradle'
    args: ['check']
    id: Test
```

> `gradle check` incluye `integrationTest`, que levanta contenedores. Si el
> *builder* de Cloud Build no puede ejecutar Docker dentro de Docker, cambia
> este paso por `args: ['test']` y ejecuta `integrationTest` en un *trigger*
> aparte con una máquina que sí lo permita. Compruébalo en el primer despliegue
> en lugar de suponerlo.

- [ ] **Step 5: Escribir el `README.md`**

Debe cubrir, como mínimo: cómo arrancar en local (`SPRING_PROFILES_ACTIVE=dev
./gradlew bootRun`), cómo generar una clave de firma, cómo ejecutar cada suite
(`test` e `integrationTest`), la tabla de endpoints de §6 del spec, y cómo
configurar un consumidor:

```yaml
# En MA-TrafficFlow-Backend, sin escribir código:
spring.security.oauth2.resourceserver.jwt:
  jwk-set-uri: https://auth.mobile-americas.com/authorization-api/.well-known/jwks.json
  audiences: trafficflow
```

- [ ] **Step 6: Verificar el arranque completo**

```bash
./gradlew clean check
./gradlew bootJar
docker build -t ma-authorization:local .
docker run --rm -p 8081:8081 -p 18081:18081 \
  -e SPRING_PROFILES_ACTIVE=dev ma-authorization:local &
sleep 25
curl -s localhost:18081/actuator/health/readiness
curl -s localhost:8081/authorization-api/.well-known/jwks.json
```

Esperado: `{"status":"UP"}` y un JWKS con `"keys"` que **no** contenga `"d"`.

Comprobar que el apagado es ordenado:

```bash
docker ps --filter ancestor=ma-authorization:local --format '{{.ID}}' | xargs docker stop
```

Esperado: el contenedor para en menos de 30 s y el log muestra el cierre de
Spring. Si tarda los 10 s del *timeout* y muere de golpe, el `ENTRYPOINT` no
está en forma exec.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
build: configuración y despliegue coherentes

server.port pasa a leer SERVER_PORT, que es la causa raíz de que el
servicio no estuviera en uso: el Service apunta a 8081 y la aplicación
escuchaba en 18080.

ENTRYPOINT en forma exec para que SIGTERM llegue a la JVM y el
terminationGracePeriodSeconds sirva de algo. Imagen JRE 25 sin root en
lugar de JDK 17 como root.

Corrige la errata sms-ma-shaplatform del nombre de la imagen y elimina el
paso envsubst: los client ID de Google viven ahora en la base de datos.

Añade probes de liveness y readiness, que no existían.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Verificación final de la fase

- [ ] `./gradlew clean check` en verde: suite unitaria **y** de integración contra los dos motores.
- [ ] `grep -rn "import jakarta\.\|import org.springframework\." src/main/java/**/domain/` no devuelve nada.
- [ ] `grep -rn "Entity" src/main/java/**/application src/main/java/**/domain` no devuelve nada.
- [ ] `curl /v1/authorization/env` no responde.
- [ ] El JWKS no contiene `"d"`, `"p"` ni `"q"`.
- [ ] El contenedor para ordenadamente ante `docker stop`.
- [ ] Existe un test que reproduce la escalada de privilegios de `develop` y exige que falle.
- [ ] Existe un test que comprueba el aislamiento entre apps por `aud`.
- [ ] Existe un test que comprueba que reutilizar un refresh rotado revoca la familia.

## Pasos manuales, fuera del código

Estos **no** los puede hacer el plan y hay que coordinarlos:

1. **Generar el par de claves** y crear el Secret:
   `kubectl create secret generic ma-auth-jwt-keys --from-file=active.jwk=./active.jwk`
2. **Sembrarlo desde Secret Manager** en Cloud Build, siguiendo el patrón de
   `MA-MtSender` (`gcloud secrets versions access latest --secret=…`).
3. **Poner los `google_client_id` reales** de `admin` y `fgf` en `auth_app` —
   `V2__datos_iniciales.sql` deja marcadores `PENDIENTE-*` a propósito.
4. **Poner los emails reales** de los dos usuarios, por el mismo motivo.
5. **Crear el repositorio de Artifact Registry** y **reapuntar los *triggers*** de
   Cloud Build, que se configuran fuera de git.
6. **Crear una base de datos NUEVA Y VACÍA** con `utf8mb4` en MySQL, y
   repuntar `DB_MA_PLATFORM_URL` del ConfigMap a ella.
   ⚠️ Corregido tras la revisión final. El ConfigMap apuntaba a
   `ma_platform_auth`, el esquema que poblaba el servicio anterior con
   `generate-ddl: true` y del que salió el volcado que reproduce `V2`. Flyway,
   con `baseline-on-migrate` en su valor por defecto (`false`), encuentra un
   esquema no vacío sin tabla de historia y **aborta**: el contexto falla, el pod
   nunca pasa la probe y el servicio queda inalcanzable — el mismo resultado que
   esta reescritura existe para eliminar, llegando por el otro lado. Ni este
   paso ni el README lo decían.
   **No usar `baseline-on-migrate: true` para sortearlo**: saltaría `V1` en
   silencio y dejaría la aplicación corriendo contra las tablas viejas. Falla
   abierto donde ahora falla cerrado.

## Después de esta fase

- **Fase 2 (Administración):** CRUD de las 5 entidades, `auth_audit` en la misma
  transacción, `@PreAuthorize` por permiso, OpenAPI publicado. Plan propio.
- **Fase 3 (Integración):** app `trafficflow`, *resource server* en
  `MA-TrafficFlow-Backend`, cabecera en `MA-TrafficFlow-UI`, adaptación de
  `MA-Platform-UI` a las cookies `HttpOnly`. Plan propio; toca tres repositorios.
