# El auth en Cloud Run — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** que `it@mobile-americas.com` y `difgar@gmail.com` inicien sesión en
`admin.mobile-americas.com` y en `traffic.mobile-americas.com` contra el auth nuevo,
desplegado en Cloud Run con su base `ma_auth` en la PostgreSQL compartida.

**Architecture:** el auth (Spring Authorization Server, Spring Boot 4, Java 25) corre como
un Cloud Run de una sola instancia en `sms-ma-platform`, con identidad y secretos propios,
y se conecta a `ma-platform-db-pgsql` por el conector de Cloud SQL. Un Terraform propio
(`terraform/` de este repo) declara solo sus recursos. La base, el url-map y los usuarios
se cambian a mano con scripts en `shared/`. El admin nuevo sale por su trigger de siempre,
hacia su bucket.

**Tech Stack:** Spring Boot 4, Flyway, PostgreSQL 18 (Cloud SQL), Terraform ≥ 1.9 con
`hashicorp/google ~> 6.0`, Cloud Run v2, Secret Manager, Cloud Build, gcloud.

**Spec:** `docs/superpowers/specs/2026-10-03-auth-en-cloud-run-design.md`

## Global Constraints

- Proyecto `sms-ma-platform` (número `893694292708`), región `us-east1`.
- **Ningún `.tf` declara la base `ma-platform-db-pgsql` ni el LB `ma-platform-lb`.** Solo
  `*_iam_member` sobre recursos ajenos.
- Issuer: `https://auth.mobile-americas.com/authorization-api`. Context path
  `/authorization-api`. Puerto de servicio 8081, gestión 18081.
- Cloud Run: mín 1, máx 1, `cpu_idle = true`, ingress `INTERNAL_LOAD_BALANCER`,
  `invoker_iam_disabled`.
- Pool de la base: máx 3, mín en reposo 1. `ApplicationName`:
  `ma-platform-auth/${K_REVISION:local}`, recortado a 63.
- CORS: `https://admin.mobile-americas.com,https://fgf.mobile-americas.com,https://traffic.mobile-americas.com`.
- Usuarios: `it@mobile-americas.com` y `difgar@gmail.com`, rol `admin` en `admin`
  (`c0000000-…0001`) y en `trafficflow` (`c0000000-…0006`).
- Secretos: los valores nunca pasan por el state de Terraform ni se imprimen. `printf`, no
  `echo`, al cargarlos.
- Sin CI: imágenes construidas a mano y fijadas por digest.
- Un PR por repositorio. Paradas para el visto bueno de difgar antes del url-map (Task 7)
  y del admin (Task 9).
- Terraform con
  `export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token --account=it.mobile.americas@gmail.com)"`.

## Review Focus

1. **El `issuer` del documento de descubrimiento detrás del LB.** Si el auth no respeta
   `X-Forwarded-Proto` y `Host`, el discovery anuncia `http://…` o la URL `run.app`, y MS-2
   rechaza todos los tokens. Se espera el issuer exacto, en `https`. Lo comprueba la Task 8.
2. **El login federado que vuelve a la URL equivocada.** Google debe volver a
   `https://auth.mobile-americas.com/authorization-api/login/oauth2/code/google`, no a una
   `run.app`; si no, `redirect_uri_mismatch`. Lo comprueba el login real de la Task 10.
3. **Un correo que no es usuario** (por ejemplo una cuenta de Google cualquiera) tiene que
   acabar en `/acceso?motivo=…` del admin, no en un 500. Comprobación manual en la Task 10.
4. **Reinicio de la instancia a mitad de un login.** Pierde ese login (el almacén está en
   memoria), pero el siguiente intento tiene que funcionar. Se documenta; no se prueba.
5. **Conexiones de la base compartida.** El auth no puede pasar de 3. Lo comprueba la Task 6
   en `pg_stat_activity`.

---

## Mapa de ficheros

**`MA-Platform-Authorization`** (rama `produccion-cloud-run`):
- Create: `src/main/resources/db/migration/V7__trafficflow_en_traffic.sql`
- Modify: `src/integrationTest/java/com/mobileamericas/authorization/MigracionIT.java:163-166`
- Modify: `src/integrationTest/java/com/mobileamericas/authorization/oauth/RegistroDeClientesIT.java:53-56`
- Modify: `build.gradle` (conector)
- Modify: `src/main/resources/application.yml` (pool y `ApplicationName`)
- Create: `src/main/java/com/mobileamericas/authorization/config/NombreDeConexion.java` y su test
- Modify: `cloudbuild.yaml` (solo construir)
- Create: `terraform/` (`versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`, `terraform.tfvars`, `imagenes.auto.tfvars`)
- Create: `shared/` (`README.md`, `db/crear-base.sh`, `db/usuarios.sql`, `secretos/cargar.sh`, `urlmap/…`)
- Create: `scripts/construir-imagen.sh`
- Delete (Task 11): `kubernetes/`

**`MA-Platform-UI`**: `.gitignore`.

---

### Task 1: V7 — la app `trafficflow` en `traffic.`

**Files:** V7 nueva; `MigracionIT.java:163-166`; `RegistroDeClientesIT.java:53-56`.

- [ ] **Step 1: Los tests piden `traffic.`** En `MigracionIT`:
```java
        assertThat(trafficflow.redirectUris()).isEqualTo(
                "https://traffic.mobile-americas.com/callback,http://localhost:5174/callback");
        assertThat(trafficflow.postLogoutRedirectUris()).isEqualTo(
                "https://traffic.mobile-americas.com/,http://localhost:5174/");
```
En `RegistroDeClientesIT`:
```java
        assertThat(c.getRedirectUris()).containsExactlyInAnyOrder(
                "https://traffic.mobile-americas.com/callback", "http://localhost:5174/callback");
        assertThat(c.getPostLogoutRedirectUris()).containsExactlyInAnyOrder(
                "https://traffic.mobile-americas.com/", "http://localhost:5174/");
```
Si `MigracionIT` comprueba también la columna `url`, pedir `https://traffic.mobile-americas.com`.

- [ ] **Step 2: Verlos fallar.**
Run: `./gradlew integrationTest --tests '*MigracionPostgresIT' --tests '*RegistroDeClientesPostgresIT'`
Expected: FAIL; las aserciones de `trafficflow` reciben `tf.`.

- [ ] **Step 3: V7**
```sql
-- El panel de TrafficFlow se movio a traffic.mobile-americas.com; tf. son ahora los clics
-- (decision de difgar, 2026-10-02). Migracion nueva y no edicion de V5: las bases que ya
-- aplicaron V5 fallarian por checksum.
UPDATE auth_app
SET url                       = 'https://traffic.mobile-americas.com',
    redirect_uris             = 'https://traffic.mobile-americas.com/callback,http://localhost:5174/callback',
    post_logout_redirect_uris = 'https://traffic.mobile-americas.com/,http://localhost:5174/',
    updated_at                = TIMESTAMP '2026-10-03 00:00:00'
WHERE name = 'trafficflow';
```

- [ ] **Step 4: Verlos pasar, en los dos motores, y la suite entera.**
Run: `./gradlew clean test integrationTest`
Expected: todo en verde (MySQL y PostgreSQL).

- [ ] **Step 5: Commit** `feat: V7, el panel de trafficflow se sirve en traffic.mobile-americas.com`

### Task 2: Conector, pool y nombre de las conexiones

**Files:** `build.gradle`; `application.yml` (bloque `datasource`); `NombreDeConexion.java` y su test.

- [ ] **Step 1: Test que falla**: `NombreDeConexionTest`, con dos casos: un nombre de 80
  caracteres se recorta a 63 conservando el prefijo `ma-platform-auth/`, y uno corto se deja
  igual. Más `ConectorCloudSqlTest`: `Class.forName("com.google.cloud.sql.postgres.SocketFactory")`
  no lanza excepción. Los dos son el mismo patrón que MS-2 (`MA-TrafficFlow-Backend`,
  `core/config/`), con el paquete del auth.
- [ ] **Step 2:** `./gradlew test --tests '*NombreDeConexionTest' --tests '*ConectorCloudSqlTest'` → FAIL: la clase no existe y `ClassNotFoundException`.
- [ ] **Step 3: Implementación**
  - `build.gradle`: `runtimeOnly 'com.google.cloud.sql:postgres-socket-factory:1.30.0'`.
  - `NombreDeConexion`: un `BeanPostProcessor` sobre `HikariDataSource`, como el de MS-2.
  - `application.yml`:
```yaml
    hikari:
      # BASE COMPARTIDA (ma-platform-db-pgsql, 50 conexiones para tres proyectos): 3 y no 20.
      minimum-idle: ${DB_POOL_MIN_IDLE:1}
      maximum-pool-size: ${DB_POOL_MAX:3}
      pool-name: AuthHikariCP
      data-source-properties:
        ApplicationName: ${DB_APPLICATION_NAME:ma-platform-auth/${K_REVISION:local}}
```
  Comprobar que un test de integración no dependía del pool de 20 ni del mínimo de 5.
- [ ] **Step 4:** `./gradlew clean test integrationTest` → todo verde.
- [ ] **Step 5: Commit** `feat: conector de Cloud SQL, pool de 3 y conexiones con nombre`

### Task 3: La base `ma_auth` y la prueba de las migraciones en PG 18

**Files:** `shared/db/crear-base.sh` y `shared/README.md`.

- [ ] **Step 1: Script** (calcado de `MA-TrafficFlow-Infra/shared/db/crear-base.sh`):
  - crea los secretos `ma-auth-db-user` (valor `ma_auth`) y `ma-auth-db-password`
    (aleatorio, con `printf`) en Secret Manager de `sms-ma-platform`, si no existen;
  - crea el rol `ma_auth` con login y sin superusuario, y concede `grant ma_auth to postgres`
    (necesario para crear una base cuyo dueño es otro rol);
  - crea la base `ma_auth` con dueño `ma_auth`;
  - hace `revoke connect … from public` y `grant connect` a `ma_auth`;
  - comprueba al final rol, dueño y que `ma_auth` puede iniciar sesión.
  
  Las credenciales de admin salen de `ma-platform-db-pgsql-postgres-{user,password}`. Se
  conecta por `cloud-sql-proxy … --port 15441 --gcloud-auth`.
- [ ] **Step 2:** ejecutarlo. Expected: `rol ma_auth super=false`, `base ma_auth dueno=ma_auth`, login OK.
- [ ] **Step 3: Migraciones con ROLLBACK, como `ma_auth`**: concatenar en un fichero
  `BEGIN;`, V1, V2, V3, `migration-vendor/postgresql/V4__sesion.sql`, V5, V6, V7, una
  consulta de comprobación y `ROLLBACK;`, y ejecutarlo con `psql -v ON_ERROR_STOP=1`.
  Expected: sin errores; `select count(*) from auth_app` = 3, y la app `trafficflow` con url
  `https://traffic…`. Después `\dt` en `ma_auth` no devuelve nada.
  Si algo falla en PG 18, **parar**: es un defecto de las migraciones y va al PR con su test.
- [ ] **Step 4: Commit** `ops: la base ma_auth en la PostgreSQL compartida, probada en PG 18`

### Task 4: Terraform del auth, primera parte (sin servicio)

**Files:** `terraform/versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`, `terraform.tfvars`.

- [ ] **Step 1: Bucket del state** (paso manual, una sola vez):
  `gcloud storage buckets create gs://ma-platform-auth-tfstate --project=sms-ma-platform --location=us-east1 --uniform-bucket-level-access --public-access-prevention` y `--versioning`.
- [ ] **Step 2: `.tf`.** Backend gcs `ma-platform-auth-tfstate`, prefijo `prod`; provider
  `~> 6.0`. Recursos:
  - APIs que falten: `run`, `secretmanager`, `artifactregistry`, `sqladmin`, `cloudbuild`,
    con `disable_on_destroy = false`.
  - Artifact Registry `ma-authorization` (DOCKER, us-east1) con limpieza: conservar las 10
    últimas.
  - SA `ma-authorization` y SA `ma-authorization-build`, más el bucket
    `sms-ma-platform-ma-authorization-build` (objectAdmin + legacyBucketReader para la SA de
    build, artifactregistry.writer, logging.logWriter).
  - Secretos vacíos: `ma-auth-google-client-id`, `ma-auth-google-client-secret`,
    `ma-auth-jwk`. Los dos de la base los crea `shared/db/crear-base.sh`.
  - IAM: `secretAccessor` de la SA del servicio sobre los cinco secretos, y
    `roles/cloudsql.client` en el proyecto.
  - El Cloud Run, el NEG, el backend y Cloud Armor van en un bloque que se crea solo cuando
    `var.imagen` no es null (Task 6). Esta primera parte no los aplica.
- [ ] **Step 3:** `terraform init && terraform validate && terraform plan -out=tfplan`.
  Expected: solo `create`, nada fuera de lo listado. `terraform apply tfplan`.
- [ ] **Step 4: Commit** `ops: terraform propio del auth: registro, identidades y secretos`

### Task 5: Valores de los secretos

**Files:** `shared/secretos/cargar.sh`.

- [ ] **Step 1: Script.** Lee `../MA-Platform-UI/client_secret.json` con `python3` (las
  claves `web.client_id` y `web.client_secret`) y añade una versión a cada secreto con
  `printf '%s' … | gcloud secrets versions add … --data-file=-`. Genera la JWK (RSA 2048,
  `use=sig`, `kid=prod-2026-10`) con `java` y la biblioteca nimbus que ya está en el
  classpath del auth (`./gradlew -q` con una tarea `generarJwk` en `build.gradle`), sin
  escribirla a disco fuera de una tubería. Nunca imprime valores.
- [ ] **Step 2:** ejecutarlo. Expected: versión 1 en los tres secretos
  (`gcloud secrets versions list`). La JWK es un JSON con `"kty":"RSA"` y `"d"`, comprobado
  sin imprimirla (`… | python3 -c 'import json,sys; k=json.load(sys.stdin); print(k["kty"], "d" in k, k["kid"])'`).
- [ ] **Step 3:** mover `MA-Platform-UI/client_secret.json` fuera del repo, a
  `~/Documents/sms-americas/secretos-locales/`, y añadir `client_secret*.json` al
  `.gitignore` de `MA-Platform-UI` (su PR).
- [ ] **Step 4: Commit** (los dos repos).

### Task 6: La imagen y el Cloud Run

**Files:** `cloudbuild.yaml`, `scripts/construir-imagen.sh`, `terraform/main.tf` (bloque del servicio), `terraform/imagenes.auto.tfvars`.

- [ ] **Step 1: `cloudbuild.yaml` solo construye**:
  - `gradle:jdk25` con `./gradlew bootJar`;
  - `docker build -t ${_IMAGE} .`;
  - `images: ['${_IMAGE}']`.
  
  Sin `gke-deploy`.
- [ ] **Step 2: `scripts/construir-imagen.sh`** (el de TrafficFlow, con un solo servicio):
  `gcloud builds submit` con la SA y el bucket de build, y escribe `imagen = "…@sha256:…"`
  en `terraform/imagenes.auto.tfvars`.
- [ ] **Step 3: Bloque del servicio en `main.tf`**:
  - `google_cloud_run_v2_service.auth` con la configuración de la tabla del spec, con
    variables literales y secretos con `secret_key_ref`;
  - la JWK montada como volumen de secreto en `/etc/ma-auth/keys` (fichero `active.jwk`);
  - sondas en el puerto 18081 (`startup_probe`: `/actuator/health/readiness`, 5 s, 36
    intentos);
  - `lifecycle { ignore_changes = [scaling] }` (lección de TrafficFlow);
  - además: NEG serverless `ma-authorization-neg`, backend `ma-authorization-be`
    (EXTERNAL_MANAGED, HTTPS, logs al 100 %), Cloud Armor `ma-authorization` (permitir todo,
    con freno por IP en preview en `/authorization-api/oauth2/token`), y
    `loadBalancerServiceUser` no hace falta (mismo proyecto).
- [ ] **Step 4:** construir la imagen; `plan` (solo `create` del bloque del servicio);
  `apply`. Expected: Cloud Run `Ready`. En los logs: Flyway aplicó 7 migraciones en
  `ma_auth`. En `pg_stat_activity`: `ma-platform-auth/<revisión>` con ≤ 3 conexiones. Si el
  primer arranque falla por la API `sqladmin` o por permisos, es lo mismo que pasó en
  TrafficFlow: arreglarlo en Terraform, no a mano.
- [ ] **Step 5: Commit** `ops: el auth en Cloud Run, construido por digest`

### Task 7: url-map — PARADA para el visto bueno de difgar

**Files:** `shared/urlmap/` (copiado de `MA-TrafficFlow-Infra/shared/urlmap/`).

- [ ] **Step 1: El cambio, como fragmento propio.** El host `auth.` hoy usa
  `path-matcher-7`, que es de la plataforma. Fragmento con prefijo `ma-platform-auth-`:
  - un path matcher `ma-platform-auth` con `defaultService` = `map-bk-default-prod` (lo de
    hoy) y `prefixMatch: /authorization-api/` → `ma-authorization-be`;
  - el host rule de `auth.mobile-americas.com` apunta a `ma-platform-auth`.
  
  Como el host ya pertenece a una regla ajena, `urlmap_merge.py` lo rechazará: añadirle
  `--reclaim-host auth.mobile-americas.com`, que solo quita ese host de la regla ajena (y la
  regla si se queda vacía; `path-matcher-7` sin referencias se borra también), con su test.
- [ ] **Step 2: Tests del url-map**:
  - `auth./authorization-api/.well-known/openid-configuration` → `ma-authorization-be`;
  - `auth./` → `map-bk-default-prod`;
  - `traffic./` → panel (sin cambios);
  - `portal.play-on.vip/` → bucket de MA-Portal (sin cambios).
- [ ] **Step 3:** `apply.sh` sin `--apply`. Expected: `loadSucceeded` y `testPassed`, con
  un diff que solo cambia lo de `auth.`. **PARAR: enseñar el diff a difgar.**
- [ ] **Step 4:** con su visto bueno: aviso a multiportal, `--apply`, y aviso de fin.

### Task 8: Verificación pública

- [ ] `curl -s https://auth.mobile-americas.com/authorization-api/.well-known/openid-configuration`.
  Expected: 200 e `"issuer":"https://auth.mobile-americas.com/authorization-api"`; todos los
  endpoints en `https://auth.mobile-americas.com/authorization-api/…` (Review Focus 1).
  Si sale `http://` o `run.app`, activar `server.forward-headers-strategy: framework` y
  repetir la Task 6.
- [ ] `curl -s -o /dev/null -w '%{http_code}' https://auth.mobile-americas.com/authorization-api/oauth2/jwks` → 200, con `kid` `prod-2026-10`.
- [ ] `curl -s -o /dev/null -w '%{http_code}' https://auth.mobile-americas.com/` → igual que antes del cambio.

### Task 9: Usuarios y admin — PARADA para el visto bueno de difgar antes del despliegue del admin

**Files:** `shared/db/usuarios.sql`; `MA-Platform-UI/.gitignore`.

- [ ] **Step 1: `usuarios.sql`**, idempotente:
```sql
UPDATE auth_user SET email = 'it@mobile-americas.com',  updated_at = now() WHERE id = 'd0000000-0000-4000-8000-000000000001';
UPDATE auth_user SET email = 'difgar@gmail.com',        updated_at = now() WHERE id = 'd0000000-0000-4000-8000-000000000002';
DELETE FROM auth_user_role WHERE user_id IN ('d0000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000002');
INSERT INTO auth_user_role (user_id, role_id) VALUES
 ('d0000000-0000-4000-8000-000000000001','c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000001','c0000000-0000-4000-8000-000000000006'),
 ('d0000000-0000-4000-8000-000000000002','c0000000-0000-4000-8000-000000000001'),
 ('d0000000-0000-4000-8000-000000000002','c0000000-0000-4000-8000-000000000006');
```
  Se ejecuta como `ma_auth` y se comprueba con un `select` que una `auth_user`,
  `auth_user_role` y `auth_role`. Los roles de fgf de los marcadores se quitan a propósito
  (fgf fuera de alcance).
- [ ] **Step 2: Trigger del admin**:
  `gcloud builds triggers update github ma-platform-admin-trigger --update-substitutions=_AUTH_ISSUER=https://auth.mobile-americas.com/authorization-api,_OAUTH_CLIENT_ID=admin --remove-substitutions=_GOOGLE_CLIENT_ID,_PUBLIC_URL`
  (o el subcomando que corresponda al tipo de trigger), y comprobar con `describe`.
- [ ] **Step 3: Copia del bucket**: `gcloud storage cp -r gs://admin.mobile-americas.com gs://sms-ma-platform-ma-authorization-build/backup-admin-$(date +%Y%m%d)/`.
- [ ] **Step 4: PARAR y pedir el visto bueno a difgar.** Después: etiqueta
  `prod-v0.1.0` sobre `origin/develop` de `MA-Platform-UI` y push de la etiqueta; esperar el
  build (`gcloud builds list --limit=1`).
- [ ] **Step 5: Invalidar la CDN**:
  `gcloud compute url-maps invalidate-cdn-cache ma-platform-lb --path='/*' --host=admin.mobile-americas.com --project=sms-ma-platform --async`.
  Es una operación sobre el url-map compartido, pero no lo modifica. Expected: `admin.`
  sirve el `index.html` nuevo.

### Task 10: De punta a punta (difgar)

- [ ] difgar entra en `https://admin.mobile-americas.com` con `it@mobile-americas.com` y
  ve el menú con TrafficFlow.
- [ ] difgar entra en `https://traffic.mobile-americas.com` y el panel carga datos (la
  lista de redes, vacía pero sin error). En los logs de `core-prod`, ningún 401.
- [ ] Con una cuenta de Google que no sea usuario: acaba en `admin…/acceso?motivo=…`, no en
  un 500 (Review Focus 3).

### Task 11: Retirar el auth viejo y cerrar

- [ ] Borrar de GKE (`kubectl delete`): `deployment/ma-authorization-prod-deployment`, el
  HPA, los dos Services del auth (incluido el NodePort) y el ConfigMap
  `ma-authorization-prod-deployment-config`. Los Secrets `ma-authorization-auth` no los usa
  nadie más: comprobar con `kubectl get deploy -o yaml | grep ma-authorization-auth` y
  borrarlos solo si no aparece.
- [ ] Borrar el trigger `ma-authorization-trigger` (lleva `_AUTH_SECRET` en texto plano).
- [ ] Borrar `kubernetes/` del repo y actualizar el README (despliegue = Terraform + Cloud
  Run; los «Pasos manuales» pasan a `shared/README.md`).
- [ ] Revisión final del PR con un revisor nuevo; arreglos; subir; abrir el PR único de
  este repo y el de `MA-Platform-UI`.
