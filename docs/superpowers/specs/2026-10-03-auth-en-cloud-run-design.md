# El servidor de autorización en producción, sobre Cloud Run

**Fecha:** 2026-10-03 · **Estado:** aprobado por difgar en conversación; pendiente de revisar por escrito

## Para qué

Que `it@mobile-americas.com` y `difgar@gmail.com` entren con su cuenta de Google en el
**admin nuevo** (`https://admin.mobile-americas.com`, `MA-Platform-UI`) y en el **panel de
TrafficFlow** (`https://traffic.mobile-americas.com`), los dos como administradores.

Hoy no puede entrar nadie: `https://auth.mobile-americas.com/authorization-api/...` da 404.

**Éxito =** las dos cuentas inician sesión en los dos paneles, y el panel de TrafficFlow
carga datos del Admin API de MS-2, que valida el token contra el `issuer`
`https://auth.mobile-americas.com/authorization-api` y su JWKS.

## Lo que hay hoy (medido el 2026-10-02/03)

- **Nadie usa el auth viejo.** El pod `ma-authorization-prod-deployment` (GKE,
  `prod-v0.2.0`, `ef8340c`) no registra una sola petición desde el 2026-09-03. El host
  `auth.` va a `map-bk-default-prod` (nginx), que no tiene ruta hacia el pod. Su
  NodePort `30554` no lo usa ningún backend.
- **El login del admin viejo ya está roto**: llama a `auth.../api/v1/authorization/google`,
  que da 404. **fgf** (`localhost:18080` en su build) también; nadie lo usa.
- El auth nuevo (`origin/develop`) es incompatible con los clientes viejos por diseño
  (OIDC + PKCE frente al login con ID token de Google), y el admin nuevo solo funciona
  contra él. **Van juntos.**

Consecuencia: **el despliegue no puede romperle el login a nadie**, porque hoy nadie
inicia sesión.

## Decisiones (difgar, 2026-10-03)

| Decisión | Por qué |
|---|---|
| **Cloud Run, no GKE** | Exponer el NodePort obligaba a tocar los puertos con nombre del grupo de instancias del nodo de `entry` (por donde pasa el tráfico de Claro), y `set-named-ports` reemplaza la lista entera. Cloud Run usa el patrón ya probado de TrafficFlow y MA-Portal (NEG serverless), con identidad y secretos propios. Coste: ~10–15 USD/mes con CPU solo durante peticiones |
| **Base `ma_auth` en PostgreSQL** (`ma-platform-db-pgsql`), no en MySQL | Decisión de difgar. El auth ya soporta los dos motores (migraciones `migration-vendor/{mysql,postgresql}`, tests contra los dos) |
| **No nginx** | Por nginx pasa tráfico de producción (Claro, landings, entry) |
| **El cliente OAuth de Google que ya existe** (`893694292708-n6uv…`, proyecto `sms-ma-platform`) | Ya tiene la URI `https://auth.mobile-americas.com/authorization-api/login/oauth2/code/google`. Pantalla de consentimiento externa, en «Prueba», con las dos cuentas como usuarios de prueba |
| **fgf fuera de alcance** | Ya está roto y sin uso. Su fila de `auth_app` se queda como está |
| **Retirar el auth viejo de GKE** | Una vez verificado el nuevo: Deployment, Services, HPA, ConfigMap y los Secrets que solo usaba él |

## Diseño

### El servicio

- **Cloud Run `ma-authorization`** en `sms-ma-platform`, `us-east1`.
  - **Una sola instancia (mín 1, máx 1).** El almacén de autorizaciones es en memoria
    (`application.yml`, la razón de `replicas: 1` en GKE). Un reinicio o un despliegue pierde
    solo los logins a medio hacer en ese momento; las sesiones viven en la base (Spring
    Session JDBC).
  - CPU solo durante peticiones (`cpu_idle = true`). La limpieza de sesiones caducadas
    puede esperar a la siguiente petición.
  - Ingress solo LB + VPC, `invoker_iam_disabled`: lo público lo expone el url-map.
  - Puerto de servicio 8081. Sondas en el puerto de gestión `18081`
    (`/actuator/health/readiness` y `/liveness`), como en GKE.
  - Conectado a `sms-ma-platform:us-east1:ma-platform-db-pgsql` por el **conector de Cloud
    SQL** (`postgres-socket-factory`); la instancia exige `connectorEnforcement=REQUIRED`.
- **Cuenta de servicio propia** `ma-authorization@sms-ma-platform`: `roles/cloudsql.client`
  y `secretAccessor` sobre sus secretos y nada más.

### Configuración (lo que hoy es ConfigMap + Secrets de Kubernetes)

| Variable | Valor | Origen |
|---|---|---|
| `AUTH_ISSUER` | `https://auth.mobile-americas.com/authorization-api` | literal |
| `GOOGLE_REDIRECT_URI` | `https://auth.mobile-americas.com/authorization-api/login/oauth2/code/google` | literal |
| `CORS_ALLOWED_ORIGINS` | `https://admin.mobile-americas.com,https://fgf.mobile-americas.com,https://traffic.mobile-americas.com` | literal (`tf.` pasa a `traffic.`) |
| `SERVER_PORT` / `MANAGEMENT_SERVER_PORT` | `8081` / `18081` | literal |
| `JAVA_TOOL_OPTIONS`, `TZ` | los de `kubernetes/deployment.yaml` | literal |
| `DB_MA_PLATFORM_URL` | `jdbc:postgresql:///ma_auth?cloudSqlInstance=sms-ma-platform:us-east1:ma-platform-db-pgsql&socketFactory=com.google.cloud.sql.postgres.SocketFactory` | literal |
| `DB_MA_PLATFORM_USER` / `_PASSWORD` | rol `ma_auth` | Secret Manager |
| `GOOGLE_CLIENT_ID` / `_SECRET` | cliente existente | Secret Manager (cargado desde el `client_secret.json` local) |
| `JWT_KEY_LOCATIONS` | `file:/etc/ma-auth/keys/active.jwk` | Secret Manager montado como fichero |
| Pool | máximo 3, mínimo 1 en reposo (hoy 20 y 5) | nuevo, por variable |

**Las conexiones se identifican** como `ma-platform-auth/<revisión>` en `pg_stat_activity`
(convención acordada con MA-Portal para la base compartida).

### La base

- `ma_auth` en `ma-platform-db-pgsql`, **nueva y vacía**: Flyway la crea desde V1 (el
  README prohíbe `baseline-on-migrate`). Rol `ma_auth` sin `cloudsqlsuperuser`, base suya,
  sin `CONNECT` para PUBLIC. Credenciales en Secret Manager.
- **Antes de desplegar**: V1–V7 aplicadas como `ma_auth` dentro de `BEGIN … ROLLBACK`
  contra la instancia real, para confirmar que aplican en **PostgreSQL 18** (los tests
  corren en 17).
- **Presupuesto de conexiones** (50): MA-Portal ≤ ~40 en su peor caso, TrafficFlow ≤ 3,
  auth ≤ 3, pg_cron 1, Cloud SQL ~3. **Cabe, sin holgura**: dato para cuando difgar evalúe
  el tamaño de la instancia.

### Cambios de código (`MA-Platform-Authorization`, un PR)

1. **`V7__trafficflow_en_traffic.sql`**: url, `redirect_uris` y `post_logout_redirect_uris`
   de la app `trafficflow` de `tf.` a `traffic.`, conservando los de `localhost:5174`. V5 no
   se toca (checksum de Flyway en las bases que ya la aplicaron). Los tests
   (`MigracionIT`, `RegistroDeClientesIT`) piden `traffic.` y fallan antes de la V7.
2. **Conector de Cloud SQL** como dependencia de ejecución.
3. **Pool configurable** y **`ApplicationName`**.
4. **`cloudbuild.yaml` solo construye** la imagen (sin `gke-deploy`). El despliegue lo
   hace terraform, con la imagen fijada por digest.
5. **`terraform/`** con lo propio del auth, en un state propio:
   - registro de imágenes;
   - SA y bucket de build;
   - la SA del servicio y sus permisos;
   - los contenedores de los secretos, sin valores;
   - Cloud Run;
   - NEG serverless, backend service y Cloud Armor básico.

   **No declara la base ni el LB.**
6. **`kubernetes/` se borra** cuando el auth viejo esté retirado, en el mismo PR.

`MA-Platform-UI`: añadir `client_secret*.json` al `.gitignore`, en su propio PR.

### Cambios manuales en lo compartido (scripts con su «cómo se deshace»)

- Base `ma_auth` y su rol.
- Valores de los secretos: el cliente de Google sale del `client_secret.json` local, que
  después sale de la carpeta del repo; la JWK es RSA 2048 nueva; las credenciales de la
  base las genera el script. Nunca se imprimen.
- url-map: en `auth.`, `/authorization-api/*` → backend del auth. El resto de `auth.`
  sigue en `map-bk-default-prod`. Con validación con tests, diff y aviso previo a la sesión
  de MA-Portal.
- Usuarios: los correos de prueba de V2 (`usuario1@pendiente.local`,
  `usuario2@pendiente.local`) pasan a ser `it@mobile-americas.com` y `difgar@gmail.com`,
  con rol `admin` en las apps `admin` y `trafficflow`.
- Triggers:
  - `ma-authorization-trigger` se **borra**: desplegaba a GKE, y con él se va
    `_AUTH_SECRET`, guardado en texto plano.
  - `ma-platform-admin-trigger` recibe `_AUTH_ISSUER` y `_OAUTH_CLIENT_ID=admin`, y pierde
    `_GOOGLE_CLIENT_ID` y `_PUBLIC_URL`.
- Retirada del auth viejo de GKE.

## Orden, verificación y vuelta atrás

| # | Paso | Verificación |
|---|---|---|
| 1 | Código y tests → PR | Suite en verde; los tests de V7 se vieron fallar antes |
| 2 | `ma_auth` + migraciones con ROLLBACK | V1–V7 aplican en PG 18; la base queda vacía |
| 3 | Valores de los secretos | Hay versión en cada secreto, sin imprimir valores |
| 4 | Terraform + imagen | Cloud Run listo; Flyway aplicó V1–V7; la conexión se ve como `ma-platform-auth/…` |
| 5 | **url-map — parada para el visto bueno de difgar** | `validate` con tests; el diff solo añade |
| 6 | Pública | `/.well-known/openid-configuration` 200 con el `issuer` exacto; `/oauth2/jwks` 200 |
| 7 | Usuarios | Las dos cuentas, cada una con sus dos roles |
| 8 | **Admin — parada para el visto bueno de difgar**: trigger, copia del bucket, etiqueta, invalidar la CDN | `admin.` sirve el admin nuevo |
| 9 | **De punta a punta (difgar)** | Login en `admin.` y en `traffic.`; el panel carga datos |
| 10 | Retirar el auth viejo de GKE; borrar `kubernetes/` | Ya no hay pod ni servicio |

**Vuelta atrás.** Nadie usa el auth hoy, así que el riesgo es bajo:

- **Auth:** quitar la regla del url-map; `auth.` vuelve al 404 de hoy.
- **Admin:** restaurar la copia del bucket.
- **Todo:** borrar Cloud Run, secretos y `ma_auth`. No afecta a MA-Portal ni a TrafficFlow.

## Lo que este diseño NO resuelve

- **fgf.** Sigue roto hasta que se reescriba con OIDC.
- **Publicar la app de Google.** En «Prueba» solo entran los usuarios de prueba, hasta 100.
  Cada usuario nuevo de la plataforma hay que darlo de alta también allí, o publicar la app.
- **El secreto del cliente de Google estuvo en un fichero suelto.** Rotarlo en el mismo
  cliente después del despliegue.
- **La MySQL vieja** (`ma_platform_auth`) se queda como está hasta que se decida retirarla.
